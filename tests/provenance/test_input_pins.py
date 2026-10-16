#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Installer-input gate: the pixi bootstrap verifies before it runs.

tools/install-pixi downloads the locked pixi release tarball,
checks its sha256 against toolchain.lock.json, installs the
single binary, and requires its --version to equal the locked
version. Every case here runs offline against fixture locks
and fixture tarballs served over file:// URLs: a good
fixture installs and verifies; a mismatched digest, an
unavailable URL, a wrong-version binary, and a tarball with
unexpected members each fail with nothing installed; and a
verified cache satisfies an install whose URL is unavailable.
A post-hash cache replacement installs the authenticated
snapshot, never the swapped-in bytes. Exits nonzero on the
first failure. Standard library only.
"""

import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from importlib.machinery import SourceFileLoader

ROOT = os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))
SCRIPT = os.path.join(ROOT, "tools", "install-pixi")

FIXTURE_VERSION = "0.0.0-fixture"


def check(name, cond, detail=""):
    if not cond:
        print("FAIL %s %s" % (name, detail))
        sys.exit(1)
    print("ok %s" % name)


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_tarball(path, members):
    """Write a gzip tarball; members maps name to bytes."""
    with tarfile.open(path, "w:gz") as tar:
        for name in sorted(members):
            data = members[name]
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o755
            tar.addfile(info, io.BytesIO(data))


def fixture_pixi(version):
    return ("#!/bin/sh\necho pixi %s\n" % version).encode("utf-8")


def write_lock(path, version, url, sha):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump({"toolchain": {"pixi": {
            "version": version,
            "release_asset": "pixi-fixture.tar.gz",
            "release_url": url,
            "release_sha256": sha}}}, handle)


def run_install(lock, prefix, cache=None):
    cmd = [sys.executable, SCRIPT, "--lock", lock,
           "--prefix", prefix]
    if cache is not None:
        cmd += ["--cache", cache]
    return subprocess.run(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True)


def load_installer():
    loader = SourceFileLoader("install_pixi_under_test", SCRIPT)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def main():
    tmp = tempfile.mkdtemp(prefix="input-pins-")
    try:
        good_tarball = os.path.join(tmp, "pixi-good.tar.gz")
        write_tarball(good_tarball,
                      {"pixi": fixture_pixi(FIXTURE_VERSION)})
        good_sha = sha256_of(good_tarball)
        good_url = "file://%s" % good_tarball
        good_lock = os.path.join(tmp, "lock-good.json")
        write_lock(good_lock, FIXTURE_VERSION, good_url, good_sha)

        prefix = os.path.join(tmp, "prefix-good")
        proc = run_install(good_lock, prefix)
        installed = os.path.join(prefix, "bin", "pixi")
        check("positive-installs",
              proc.returncode == 0 and os.path.isfile(installed),
              proc.stdout.strip()[-200:])
        out = subprocess.run(
            [installed, "--version"], stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True)
        check("positive-version-exact",
              out.returncode == 0
              and out.stdout.splitlines()[0].strip()
              == "pixi " + FIXTURE_VERSION,
              out.stdout.strip()[-120:])

        bad_lock = os.path.join(tmp, "lock-bad-sha.json")
        write_lock(bad_lock, FIXTURE_VERSION, good_url, "0" * 64)
        prefix = os.path.join(tmp, "prefix-bad-sha")
        proc = run_install(bad_lock, prefix)
        check("mismatch-refuses",
              proc.returncode == 1
              and not os.path.exists(os.path.join(
                  prefix, "bin", "pixi")),
              "exit %d" % proc.returncode)
        check("mismatch-names-digest",
              "sha256" in proc.stdout.lower()
              or "digest" in proc.stdout.lower()
              or "mismatch" in proc.stdout.lower(),
              proc.stdout.strip()[-200:])

        missing_lock = os.path.join(tmp, "lock-missing.json")
        write_lock(missing_lock, FIXTURE_VERSION,
                   "file:///nonexistent-pixi-input-pins.tar.gz",
                   good_sha)
        prefix = os.path.join(tmp, "prefix-missing")
        proc = run_install(missing_lock, prefix)
        check("unavailable-refuses",
              proc.returncode == 1
              and not os.path.exists(os.path.join(
                  prefix, "bin", "pixi")),
              "exit %d" % proc.returncode)

        other_tarball = os.path.join(tmp, "pixi-other.tar.gz")
        write_tarball(other_tarball,
                      {"pixi": fixture_pixi("9.9.9-other")})
        other_lock = os.path.join(tmp, "lock-other.json")
        write_lock(other_lock, FIXTURE_VERSION,
                   "file://%s" % other_tarball,
                   sha256_of(other_tarball))
        prefix = os.path.join(tmp, "prefix-other")
        proc = run_install(other_lock, prefix)
        check("wrong-version-refuses",
              proc.returncode == 1
              and not os.path.exists(os.path.join(
                  prefix, "bin", "pixi")),
              "exit %d" % proc.returncode)

        extra_tarball = os.path.join(tmp, "pixi-extra.tar.gz")
        write_tarball(extra_tarball,
                      {"pixi": fixture_pixi(FIXTURE_VERSION),
                       "pixi-extra": b"unexpected\n"})
        extra_lock = os.path.join(tmp, "lock-extra.json")
        write_lock(extra_lock, FIXTURE_VERSION,
                   "file://%s" % extra_tarball,
                   sha256_of(extra_tarball))
        prefix = os.path.join(tmp, "prefix-extra")
        proc = run_install(extra_lock, prefix)
        check("extra-member-refuses",
              proc.returncode == 1
              and not os.path.exists(os.path.join(
                  prefix, "bin", "pixi")),
              "exit %d" % proc.returncode)

        cache = os.path.join(tmp, "cache.tgz")
        with open(good_tarball, "rb") as src:
            with open(cache, "wb") as dst:
                dst.write(src.read())
        prefix = os.path.join(tmp, "prefix-cached")
        proc = run_install(missing_lock, prefix, cache=cache)
        check("verified-cache-satisfies-offline",
              proc.returncode == 0
              and os.path.isfile(os.path.join(
                  prefix, "bin", "pixi")),
              "exit %d %s" % (proc.returncode,
                              proc.stdout.strip()[-200:]))

        installer = load_installer()
        with open(good_tarball, "rb") as handle:
            good_bytes = handle.read()
        good_payload = fixture_pixi(FIXTURE_VERSION)
        evil_payload = ("#!/bin/sh\necho pixi %s\n"
                        "echo swapped-bytes\n" % FIXTURE_VERSION
                        ).encode("utf-8")
        evil_tarball = os.path.join(tmp, "pixi-evil.tar.gz")
        write_tarball(evil_tarball, {"pixi": evil_payload})
        race_cache = os.path.join(tmp, "race-cache.tgz")
        with open(race_cache, "wb") as handle:
            handle.write(good_bytes)
        race_pin = {"version": FIXTURE_VERSION,
                    "url": "file:///nonexistent-input-pins.tar.gz",
                    "sha": good_sha}
        snapshot, error = installer.fetch(race_pin, race_cache)
        check("post-hash-snapshot-verified",
              snapshot == good_bytes, error)
        with open(evil_tarball, "rb") as handle:
            evil_bytes = handle.read()
        with open(race_cache, "wb") as handle:
            handle.write(evil_bytes)
        race_prefix = os.path.join(tmp, "prefix-race")
        code = installer.install_from(snapshot, race_pin,
                                      race_prefix)
        installed = os.path.join(race_prefix, "bin", "pixi")
        staged = None
        if os.path.isfile(installed):
            with open(installed, "rb") as handle:
                staged = handle.read()
        check("post-hash-replacement-ignored",
              code == 0 and staged == good_payload
              and staged != evil_payload,
              "exit %d" % code)

        proc = subprocess.run(
            [sys.executable, SCRIPT, "--bogus-flag"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True)
        check("usage-error-exits-2", proc.returncode == 2,
              "exit %d" % proc.returncode)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("input-pins: all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
