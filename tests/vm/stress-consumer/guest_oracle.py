#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Guest-targeted oracle module for the pinned stress guest.

The stress guest boots 7.0.14-070014-generic while the host
runs another kernel, so the host-built oracle module (whose
vermagic names the host release) is unloadable there. This
module binds the reviewed fixture built offline from the
publisher-signed 7.0.14 kbuild headers: every armed run
re-hashes the fixture bytes, parses the vermagic from the
bytes, and stamps the digest into the run manifest, and the
guest re-hashes the same bytes before a normal load (no
--force, ever).

Re-derivation (audited, offline): fetch the two header debs
named below, authenticate them against the publisher-signed
CHECKSUMS (Kernel PPA key 60AA7B6F30434AE68E569963
E50C6A0917C622B0 from the publisher keyserver), extract
them, and rebuild with the provenance build command;
byte-identical output is the pass criterion.
"""

import hashlib
import json
import os
import shutil
import struct
import subprocess
import tempfile

GUEST_RELEASE = "7.0.14-070014-generic"
GUEST_VERMAGIC = "7.0.14-070014-generic SMP preempt mod_unload modversions "

# Publisher-signed header inputs (shas from the verified
# CHECKSUMS; sizes in bytes).
HEADER_DEBS = (
    {"name": "linux-headers-7.0.14-070014_"
             "7.0.14-070014.202606271041_all.deb",
     "sha256": "20ff1bba352b3468f421d0bf0bf781909adc67c27f060a57"
               "1d06fa208ed1427a",
     "size": 14773966},
    {"name": "linux-headers-7.0.14-070014-generic_"
             "7.0.14-070014.202606271041_amd64.deb",
     "sha256": "531ecccf087c21da698aa43ad8c7a9b8f5b94a63dc2bb2e59"
               "d67d419ee4e0543",
     "size": 4126324},
)
HEADER_BASE_URL = "https://kernel.ubuntu.com/mainline/v7.0.14/amd64/"
SIGNING_FINGERPRINT = "60AA7B6F30434AE68E569963E50C6A0917C622B0"

# The reviewed fixture this module binds.
KO_SHA256 = "923c708278a8dc0ad96a897bb2d3ed75ef35a521428a87fdb07" \
    "d58d30cd58cfc"
KO_SIZE = 50448

# Live-measured /sys/kernel/btf/vmlinux bytes on the pinned
# guest build during matrix qualification: the guest identity
# pin, re-checked against live bytes on every run.
GUEST_BTF_SHA256 = "ec3aa895be1da974a3116c24cd31adccc5e49fef1b4b089" \
    "dc588aa9e32419a05"

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(
    os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
FIXTURE_KO = os.path.join(
    REPO, "tests", "vm", "fixtures", "ko",
    "memveil_dma_oracle-7.0.14-070014-generic.ko")
FIXTURE_PROVENANCE = FIXTURE_KO + ".provenance.json"


def sha_file(path):
    """SHA-256 of a file, streamed."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1048576), b""):
            digest.update(chunk)
    return digest.hexdigest()


def vermagic_from_bytes(path):
    """Read the vermagic string from a .ko without modinfo.

    Parses the ELF section table for .modinfo and returns
    the vermagic= value. Pure Python so the guest (which
    must not depend on kmod tooling for a load gate) and
    the host run the same check. Raises ValueError when
    the bytes are not a well-formed module carrying one.
    """
    with open(path, "rb") as handle:
        blob = handle.read()
    if blob[:4] != b"\x7fELF" or len(blob) < 64:
        raise ValueError("not an ELF object: %s" % path)
    elf_class = blob[4]
    if blob[5] != 1:
        raise ValueError("not little-endian ELF: %s" % path)
    if elf_class == 1:
        if len(blob) < 52:
            raise ValueError("truncated ELF header in %s" % path)
        shoff = struct.unpack("<L", blob[32:36])[0]
        shentsize = struct.unpack("<H", blob[46:48])[0]
        shnum = struct.unpack("<H", blob[48:50])[0]
        shstrndx = struct.unpack("<H", blob[50:52])[0]
        entry = "<LLLLLLLLLL"
        entry_size = 40
    elif elf_class == 2:
        if len(blob) < 64:
            raise ValueError("truncated ELF header in %s" % path)
        shoff = struct.unpack("<Q", blob[40:48])[0]
        shentsize = struct.unpack("<H", blob[58:60])[0]
        shnum = struct.unpack("<H", blob[60:62])[0]
        shstrndx = struct.unpack("<H", blob[62:64])[0]
        entry = "<LLQQQQIIQQ"
        entry_size = 64
    else:
        raise ValueError("unknown ELF class in %s" % path)
    if shentsize < entry_size or shnum == 0 \
            or shoff + shentsize * shnum > len(blob):
        raise ValueError("truncated section table in %s" % path)

    def section(index):
        at = shoff + index * shentsize
        if at + entry_size > len(blob):
            raise ValueError("truncated section entry in %s" % path)
        fields = struct.unpack(entry, blob[at:at + entry_size])
        return {"name_off": fields[0], "offset": fields[4],
                "size": fields[5]}

    if shstrndx >= shnum:
        raise ValueError("bad string section index in %s" % path)
    strings = section(shstrndx)
    strtab = blob[strings["offset"]:strings["offset"] + strings["size"]]

    def name(off):
        end = strtab.find(b"\0", off)
        if end < 0:
            raise ValueError("unterminated section name in %s" % path)
        return strtab[off:end].decode("ascii", "replace")

    for index in range(shnum):
        sect = section(index)
        if name(sect["name_off"]) != ".modinfo":
            continue
        if sect["offset"] + sect["size"] > len(blob):
            raise ValueError("truncated .modinfo in %s" % path)
        for field in blob[sect["offset"]:sect["offset"] + sect["size"]].split(
                b"\0"):
            if field.startswith(b"vermagic="):
                return field[len("vermagic="):].decode(
                    "ascii", "replace")
        raise ValueError("no vermagic in .modinfo of %s" % path)
    raise ValueError("no .modinfo section in %s" % path)


def verify_fixture(ko_path=None, provenance_path=None):
    """Verify the fixture bytes against the pinned binding.

    Returns the provenance receipt dict. Raises ValueError
    on any drift: missing files, digest or size mismatch,
    receipt mismatch, or a vermagic that does not name the
    pinned guest release exactly.
    """
    ko_path = ko_path or FIXTURE_KO
    provenance_path = provenance_path or FIXTURE_PROVENANCE
    if not os.path.isfile(ko_path):
        raise ValueError("oracle fixture missing: %s" % ko_path)
    if not os.path.isfile(provenance_path):
        raise ValueError("oracle provenance missing: %s"
                         % provenance_path)
    with open(provenance_path) as handle:
        receipt = json.load(handle)
    got = sha_file(ko_path)
    if got != KO_SHA256:
        raise ValueError("oracle fixture digest drift: %s..." % got[:16])
    if os.path.getsize(ko_path) != KO_SIZE:
        raise ValueError("oracle fixture size drift")
    if receipt.get("ko_sha256") != KO_SHA256:
        raise ValueError("oracle receipt digest drift")
    if receipt.get("target_release") != GUEST_RELEASE:
        raise ValueError("oracle receipt release drift")
    magic = vermagic_from_bytes(ko_path)
    if magic != GUEST_VERMAGIC:
        raise ValueError("oracle vermagic %r names no pinned guest"
                         % magic)
    if receipt.get("vermagic") != GUEST_VERMAGIC:
        raise ValueError("oracle receipt vermagic drift")
    return receipt


def kbuild_root():
    """Headers cache root holding the extracted kbuild tree."""
    override = os.environ.get("MEMVEIL_KBUILD_ROOT", "")
    if override:
        return override
    return os.path.join(
        os.path.expanduser("~"), ".cache", "memveil-kbuild",
        GUEST_RELEASE)


def rebuild_from_kbuild(scratch, kbuild=None):
    """Rebuild the oracle from the extracted headers (audit).

    Compiles tests/kernel/memveil_dma_oracle.c offline
    against the extracted publisher headers with the
    provenance build command and returns the fresh .ko
    path. Byte-equality with the fixture is the caller's
    pass criterion. Raises ValueError when the headers
    cache is absent or fails its own hash check.
    """
    root = kbuild or kbuild_root()
    tree = os.path.join(
        root, "tree", "usr", "src",
        "linux-headers-7.0.14-070014-generic")
    makefile = os.path.join(tree, "Makefile")
    if not os.path.isfile(makefile):
        raise ValueError(
            "no extracted 7.0.14 kbuild tree at %s "
            "(populate from the publisher header debs first)"
            % tree)
    release_path = os.path.join(
        tree, "include", "config", "kernel.release")
    try:
        with open(release_path) as handle:
            release = handle.read().strip()
    except OSError as exc:
        raise ValueError("kbuild tree unreadable: %s" % exc)
    if release != GUEST_RELEASE:
        raise ValueError("kbuild tree release %r is not %s"
                         % (release, GUEST_RELEASE))
    os.makedirs(scratch, exist_ok=True)
    build_dir = tempfile.mkdtemp(prefix="oracle-rebuild-",
                                 dir=scratch)
    kernel = os.path.join(REPO, "tests", "kernel")
    for name in ("Makefile", "memveil_dma_oracle.c",
                 "memveil_region_oracle.c"):
        shutil.copyfile(os.path.join(kernel, name),
                        os.path.join(build_dir, name))
    kflags = "-g0 -ffile-prefix-map=%s=. " \
        "-ffile-prefix-map=%s=." % (tree, build_dir)
    proc = subprocess.run(
        ["make", "-C", tree, "M=" + build_dir, "modules",
         "CC=gcc", "KCFLAGS=" + kflags],
        capture_output=True, text=True, timeout=600)
    made = os.path.join(build_dir, "memveil_dma_oracle.ko")
    if proc.returncode != 0 or not os.path.isfile(made):
        raise ValueError("oracle rebuild failed: %s"
                         % proc.stderr.strip()[-2000:])
    return made
