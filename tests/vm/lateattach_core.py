#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared core for the ported late-attach runner.

Ports the blocked late-attach gate onto the reviewed
test-only Rust consumer (tests/vm/stress-consumer/) and the
guest-targeted oracle fixture: the two late-attach phases
drive the same consumer binary with digest-pinned sealed
objects and no bridge.

This module binds every executed byte (seal, objects,
oracle fixture, pinned guest kernel, profile), stages the
consumer at build/vm/mv_consume, and writes and
re-verifies the late-attach input manifest. The object
supply points are shared with the battery core: the seal
pins live in exactly one pin file
(tests/vm/stress-consumer/stress_core.py C9_* plus the
battery profile/guest pins), so the re-pin at seal is a
pin-file change there, documented in the port report.
All judging stays with the kept late-attach judges
(tests/vm/test_late_attach.py), imported verbatim by the
runner; live boots stay in the runner.
"""

import hashlib
import json
import os
import shutil
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.join(_HERE, "stress-consumer"))

import battery_core as bcore  # noqa: E402
import lateattach_guest  # noqa: E402
import guest_oracle  # noqa: E402
import stress_core as score  # noqa: E402

SCHEMA = "memveil-lateattach-inputs/1"

# Guest-inputs delivery: the full guest argv no longer
# fits the kernel command line once vng base64-encodes the
# --exec payload into virtme.exec=, so the host stages the
# complete inputs doc in the already-shared export dir and
# the guest command line carries only this stable pointer
# filename (a fixed token: never a digest, never a host
# path). The guest resolves it against its export dir,
# hashes the exact bytes first, and refuses unless the run
# manifest binds the same digest for its case.
GUEST_INPUTS_FILE = "guest-inputs.json"
GUEST_INPUTS_SCHEMA = "memveil-lateattach-guest-inputs/1"

# The only guest release this gate admits, single-sourced
# from the guest flow. The oracle fixture loads only there,
# so the host pins below must all name it too.
EXPECT_RELEASE = lateattach_guest.EXPECT_RELEASE

# Pinned guest kernel, single-sourced from the battery
# core's frozen-lock mirror (row "7.0", archive kind): the
# vng version tag boots it, the vmlinuz sha and the modules
# manifest sha verify its cache before any boot. One pin
# file names the guest for both runners.
VNG_TAG = bcore.VNG_TAG
VMLINUZ_SHA256 = bcore.VMLINUZ_SHA256
MODULES_MANIFEST_SHA256 = bcore.MODULES_MANIFEST_SHA256

# Attach grammar shared with the retired legs
# (tests/vm/guest_lifecycle.py) and the guest flow here.
LC_SITES = lateattach_guest.LC_SITES
CP_SITES = lateattach_guest.CP_SITES

CASES = ("lateattach",)
CASE_TIMEOUTS = {
    "lateattach": 900,
}
# Late attach needs no guest network: the default microvm
# path carries both phases.
CASE_NETWORK = {
    "lateattach": False,
}

# Where the staged consumer lands under a destination root:
# the retired prerequisite path, now producer-backed. The
# armed runner stages under the repo; offline probes stage
# under a scratch dir and never touch the repo tree.
STAGED_CONSUMER_REL = os.path.join("build", "vm",
                                   "mv_consume")


def sha_file(path):
    """SHA-256 of a file, streamed."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1048576), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_head(repo):
    """Full commit of the checkout, or refusal text."""
    return bcore.git_head(repo)


def profile_pins(repo):
    """Digest pins for the bound test profile doc."""
    return bcore.profile_pins(repo)


def pinned_guest_entry(repo):
    """The frozen kernels.lock.json row this gate boots."""
    return bcore.pinned_guest_entry(repo)


def guest_binding(repo):
    """Guest-kernel binding cross-checked against the lock."""
    binding = bcore.guest_binding(repo)
    if binding["release"] != EXPECT_RELEASE:
        raise ValueError("guest release drift: %r"
                         % binding["release"])
    return binding


def materialize(repo, work, candidate_path, bundle_path):
    """Write the sealed bytes under work, verified.

    Shared supply points with the battery core: verifies
    the explicit candidate seal, extracts the sealed binary
    plus the three objects and the bound profile, and
    cross-checks the committed Aya fixtures. The lateattach
    guest executes the consumer over the sealed
    lifecycle/copy pair plus the oracle fixture; the
    attempt object, the sealed binary, and the profile ride
    as supplied slots the manifest binds. Any drift
    refuses.
    """
    return bcore.materialize(repo, work, candidate_path,
                             bundle_path)


def stage_consumer(dest_root, built):
    """Stage the built consumer at build/vm/mv_consume.

    Copies the release binary the builder hashed under the
    destination root at the retired prerequisite path and
    re-hashes the staged bytes: the staged digest must
    equal the built digest, or the stage refuses. Returns
    {path, sha256, build} for the inputs doc and the
    manifest writer. The armed runner stages under the
    repo; offline callers pass a scratch root.
    """
    src = built["path"]
    if not src or not os.path.isfile(src):
        raise ValueError("consumer build has no binary: %r"
                         % (src,))
    dst = os.path.join(dest_root, STAGED_CONSUMER_REL)
    parent = os.path.dirname(dst)
    try:
        os.makedirs(parent, exist_ok=True)
    except OSError as exc:
        raise ValueError("consumer stage dir failed: %s"
                         % exc)
    try:
        shutil.copyfile(src, dst)
        os.chmod(dst, 0o755)
    except OSError as exc:
        raise ValueError("consumer stage copy failed: %s"
                         % exc)
    got = sha_file(dst)
    if got != built["sha256"]:
        raise ValueError(
            "staged consumer drift: want %s... got %s..."
            % (built["sha256"][:16], got[:16]))
    return {"path": dst, "sha256": got,
            "build": built["build"]}


def write_input_manifest(path, inputs, consumer, cases, argv,
                         runner_commit, guest_inputs=None):
    """Write the late-attach input manifest binding every byte.

    guest_inputs maps the listed case to the staged
    guest-inputs doc path; the doc bytes are re-hashed at
    write time, so the manifest always stamps the exact
    bytes the guest must see. Bound bytes are re-hashed at
    write time, so the manifest always stamps measured
    bytes.
    """
    staged = {}
    for case, doc_path in sorted((guest_inputs or {}).items()):
        staged[case] = {
            "file": GUEST_INPUTS_FILE,
            "path": doc_path,
            "sha256": sha_file(doc_path),
        }
    manifest = {
        "schema": SCHEMA,
        "runner_commit": runner_commit,
        "runner_argv": list(argv),
        "cases": list(cases),
        "consumer": {
            "binary_sha256": consumer["sha256"],
            "build": consumer["build"],
        },
        "binary": {"path": inputs["binary"]["path"],
                   "sha256": inputs["binary"]["sha256"]},
        "objects": {
            "attempt": {"path": inputs["attempt"]["path"],
                        "sha256": inputs["attempt"]["sha256"]},
            "lc": {"path": inputs["lc"]["path"],
                   "sha256": inputs["lc"]["sha256"]},
            "cp": {"path": inputs["cp"]["path"],
                   "sha256": inputs["cp"]["sha256"]},
        },
        "guest_inputs": staged,
        "profile": {"path": inputs["profile"]["path"],
                    "sha256": inputs["profile"]["sha256"],
                    "profile_id":
                        inputs["profile"]["profile_id"]},
        "candidate": inputs["candidate"],
        "oracle": dict(inputs["oracle"],
                       ko_provenance_sha256=sha_file(
                           guest_oracle.FIXTURE_PROVENANCE)),
        "guest": inputs["guest"],
    }
    with open(path, "w") as handle:
        handle.write(json.dumps(manifest, indent=2,
                                sort_keys=True) + "\n")
    return manifest


def verify_input_manifest(manifest, consumer_path=None):
    """Re-hash every bound byte; returns a reason list (empty ok).

    The host runs this before booting and the guest re-runs
    its own input verification before attaching: both ends
    verify the bytes they use.
    """
    bad = []
    if manifest.get("schema") != SCHEMA:
        return ["manifest schema %r" % (manifest.get("schema"),)]
    for field in ("runner_commit", "runner_argv", "cases",
                  "consumer", "binary", "objects",
                  "guest_inputs", "profile", "candidate",
                  "oracle", "guest"):
        if field not in manifest:
            bad.append("manifest lacks %s" % field)
    if bad:
        return sorted(bad)
    for field in ("consumer", "binary", "objects",
                  "guest_inputs", "profile", "candidate",
                  "oracle", "guest"):
        if not isinstance(manifest.get(field), dict):
            bad.append("manifest %s is not a mapping" % field)
    if not isinstance(manifest.get("cases"), list):
        bad.append("manifest cases is not a list")
    if bad:
        return sorted(bad)
    cases = manifest.get("cases", [])
    if cases != ["lateattach"]:
        bad.append("manifest cases %r" % (cases,))
    if consumer_path is not None:
        try:
            got = sha_file(consumer_path)
        except OSError as exc:
            return ["consumer unreadable: %s" % exc]
        if got != manifest["consumer"].get("binary_sha256"):
            bad.append("consumer digest mismatch")
    blobs = [("binary", manifest["binary"])]
    for channel in ("attempt", "lc", "cp"):
        blobs.append(("%s object" % channel,
                      manifest["objects"].get(channel, {})))
    blobs.append(("profile", manifest["profile"]))
    for label, entry in blobs:
        path = entry.get("path", "")
        try:
            got = sha_file(path)
        except OSError:
            bad.append("%s unreadable: %s" % (label, path))
            continue
        if got != entry.get("sha256"):
            bad.append("%s bytes differ from manifest" % label)
    want = {"attempt": score.C9_ATTEMPT_SHA,
            "lc": score.C9_LC_SHA, "cp": score.C9_CP_SHA}
    for channel, digest in want.items():
        if manifest["objects"].get(channel, {}).get("sha256") \
                != digest:
            bad.append("%s object is not the sealed C9 bytes"
                       % channel)
    candidate = manifest.get("candidate", {})
    files = candidate.get("files", {})
    if manifest["binary"].get("sha256") != files.get(
            "bin/memveil"):
        bad.append("binary is not the sealed candidate bytes")
    for member, channel in (
            ("bpf/swiotlb_attempt.bpf.o", "attempt"),
            ("bpf/swiotlb_lifecycle.bpf.o", "lc"),
            ("bpf/swiotlb_copy.bpf.o", "cp")):
        if manifest["objects"].get(channel, {}).get("sha256") \
                != files.get(member):
            bad.append("%s object differs from the seal"
                       % channel)
    if candidate.get("source", {}).get("commit") \
            != score.C9_SOURCE_COMMIT:
        bad.append("candidate source drift")
    if candidate.get("bundle_manifest_sha256") \
            != score.C9_BUNDLE_MANIFEST_SHA:
        bad.append("candidate bundle manifest drift")
    if candidate.get("bundle", {}).get("sha256") \
            != score.C9_BUNDLE_SHA:
        bad.append("candidate bundle drift")
    if manifest["profile"].get("profile_id") \
            != bcore.PROFILE_ID:
        bad.append("profile id drift")
    if manifest["profile"].get("sha256") \
            != bcore.PROFILE_SHA256:
        bad.append("profile is not the pinned reference bytes")
    oracle = manifest.get("oracle", {})
    if oracle.get("ko_sha256") != guest_oracle.KO_SHA256:
        bad.append("oracle ko digest drift")
    if oracle.get("ko_vermagic") != guest_oracle.GUEST_VERMAGIC:
        bad.append("oracle ko vermagic drift")
    if oracle.get("btf_sha256") != guest_oracle.GUEST_BTF_SHA256:
        bad.append("oracle btf pin drift")
    if oracle.get("guest_release") != guest_oracle.GUEST_RELEASE:
        bad.append("oracle guest release drift")
    guest = manifest.get("guest", {})
    if guest.get("vng_tag") != VNG_TAG:
        bad.append("guest vng tag drift")
    if guest.get("release") != EXPECT_RELEASE:
        bad.append("guest release drift")
    if guest.get("vmlinuz_sha256") != VMLINUZ_SHA256:
        bad.append("guest vmlinuz drift")
    if guest.get("modules_manifest_sha256") \
            != MODULES_MANIFEST_SHA256:
        bad.append("guest modules drift")
    staged = manifest.get("guest_inputs", {})
    for case in cases:
        if not isinstance(case, str):
            bad.append("guest inputs lack a staged doc "
                       "for %r" % (case,))
            continue
        entry = staged.get(case, {})
        if not isinstance(entry, dict) \
                or entry.get("file") != GUEST_INPUTS_FILE:
            bad.append("guest inputs lack a staged doc "
                       "for %s" % case)
            continue
        path = entry.get("path", "")
        try:
            got = sha_file(path)
        except OSError:
            bad.append("guest inputs doc unreadable for "
                       "%s: %s" % (case, path))
            continue
        if got != entry.get("sha256"):
            bad.append("guest inputs doc bytes differ "
                       "from manifest for %s" % case)
    for case in sorted(staged):
        if case not in CASES:
            bad.append("guest inputs stage unknown case "
                       "%r" % (case,))
    return sorted(bad)
