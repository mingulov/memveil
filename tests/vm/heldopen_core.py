#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared core for the L6 held-open port.

Ports the blocked L6 live held-open leg onto the reviewed
test-only Rust consumer (tests/vm/stress-consumer/) and the
guest-targeted oracle fixture, on the battery shape:
the guest flow drives the consumer with digest-pinned
sealed objects, and the report step runs the sealed
executable staged from the same seal.

The seal pins live in heldopen_seal (which names the
retained seal; the next seal swaps that file); the pinned
guest row is derived from the battery runner
(battery_core), never re-pinned here. This module
materializes the sealed bytes, writes and re-verifies the
held-open input manifest, and refuses any drift.
"""

import hashlib
import json
import os
import sys
import tarfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "stress-consumer"))

import battery_core as battery  # noqa: E402
import guest_oracle  # noqa: E402
import heldopen_guest  # noqa: E402
import heldopen_seal as seal  # noqa: E402
import stress_core as score  # noqa: E402

SCHEMA = "memveil-heldopen-inputs/1"

# Guest-inputs delivery, same shape as the battery: the
# host stages the complete inputs doc in the already-shared
# export dir and the guest command line carries only this
# stable pointer filename (a fixed token: never a digest,
# never a host path).
GUEST_INPUTS_FILE = "heldopen-inputs.json"
GUEST_INPUTS_SCHEMA = heldopen_guest.GUEST_INPUTS_SCHEMA

# The only guest release this leg admits, single-sourced
# from the guest flow.
EXPECT_RELEASE = heldopen_guest.EXPECT_RELEASE

# Pinned guest kernel, derived from the battery runner
# (battery_core owns these constants): the vng version tag
# boots it, the vmlinuz sha and the modules manifest sha
# verify its cache before any boot.
VNG_TAG = battery.VNG_TAG
VMLINUZ_SHA256 = battery.VMLINUZ_SHA256
MODULES_MANIFEST_SHA256 = battery.MODULES_MANIFEST_SHA256

# Attach grammar shared with the battery guest flow.
LC_SITES = heldopen_guest.LC_SITES
CP_SITES = heldopen_guest.CP_SITES

CASE = heldopen_guest.CASE
CASE_TIMEOUT = 900
# The held-open window needs no pcnet NIC: microvm boot.
CASE_NETWORK = False


def sha_file(path):
    """SHA-256 of a file, streamed."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1048576), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_head(repo):
    """Full commit of the checkout, or refusal text."""
    return battery.git_head(repo)


def pinned_guest_entry(repo):
    """The frozen kernels.lock.json row this leg boots."""
    return battery.pinned_guest_entry(repo)


def guest_binding(repo):
    """Guest-kernel binding cross-checked against the lock."""
    return battery.guest_binding(repo)


def materialize(repo, work, candidate_path, bundle_path):
    """Write the sealed bytes under work, verified.

    Verifies the explicit candidate seal against the
    heldopen_seal pins (manifest digest, source, bundle
    bytes, inner manifest, all three BPF member hashes),
    then extracts the sealed executable, the
    lifecycle/copy objects, and the seal-bound 7.0
    reference profile into the run work dir. The profile
    bytes must match BOTH the outer candidate manifest
    and the sealed inner manifest, so the bound doc
    follows the seal with no separate pin. The objects
    are cross-checked byte-equal with the committed Aya
    fixtures. Returns the input dict the manifest
    carries. Any drift refuses.
    """
    os.makedirs(work, exist_ok=True)
    candidate = score.verify_candidate_binding(
        candidate_path, bundle_path,
        pins=seal.candidate_pins())
    # The binary and profile shas ride in the verified
    # manifests next to the object pins; re-hash after
    # reading so a swapped file refuses instead of
    # rebinding silently.
    try:
        with open(candidate_path) as handle:
            manifest_doc = json.load(handle)
    except (OSError, ValueError) as exc:
        raise ValueError("candidate manifest unreadable: %s"
                         % exc)
    if sha_file(candidate_path) != seal.CANDIDATE_SHA256:
        raise ValueError("candidate manifest drift on reread")
    try:
        binary_sha = manifest_doc["files"][seal.BINARY_MEMBER]
        profile_sha = manifest_doc["files"][seal.PROFILE_MEMBER]
    except KeyError:
        raise ValueError("candidate seal lacks the binary or "
                         "profile member")
    member_shas = {
        seal.BINARY_MEMBER: binary_sha,
        "bpf/swiotlb_lifecycle.bpf.o":
            candidate["files"]["bpf/swiotlb_lifecycle.bpf.o"],
        "bpf/swiotlb_copy.bpf.o":
            candidate["files"]["bpf/swiotlb_copy.bpf.o"],
        seal.PROFILE_MEMBER: profile_sha,
    }
    try:
        archive = tarfile.open(bundle_path, "r:gz")
    except (tarfile.TarError, OSError) as exc:
        raise ValueError("candidate bundle unreadable: %s" % exc)
    try:
        entries = archive.getmembers()
        members = {m.name: m for m in entries if m.isfile()}
        # The tarball bytes are already digest-bound by the
        # binding check above, so the top dir is
        # authenticated: read it from the members instead
        # of pinning one seal's tag.
        tops = {m.name.rstrip("/").split("/")[0]
                for m in entries}
        if len(tops) != 1:
            raise ValueError(
                "candidate bundle has no single top dir")
        root = tops.pop() + "/"
        inner = members.get(root + "MANIFEST.json")
        if inner is None:
            raise ValueError(
                "candidate bundle lacks inner manifest")
        handle = archive.extractfile(inner)
        if handle is None:
            raise ValueError(
                "candidate bundle lacks inner manifest")
        try:
            inner_doc = json.loads(handle.read().decode("utf-8"))
        except ValueError as exc:
            raise ValueError("sealed inner manifest "
                             "unparsable: %s" % exc)
        inner_files = inner_doc.get("files", {})
        if inner_files.get(seal.PROFILE_MEMBER) != profile_sha:
            raise ValueError("sealed inner manifest does not "
                             "bind the profile member")
        if inner_files.get(seal.BINARY_MEMBER) != binary_sha:
            raise ValueError("sealed inner manifest does not "
                             "bind the binary member")
        out = {}
        names = {seal.BINARY_MEMBER: "memveil",
                 "bpf/swiotlb_lifecycle.bpf.o":
                     "lifecycle.bpf.o",
                 "bpf/swiotlb_copy.bpf.o": "copy.bpf.o",
                 seal.PROFILE_MEMBER: "profile.json"}
        for member, want in sorted(member_shas.items()):
            entry = members.get(root + member)
            if entry is None:
                raise ValueError(
                    "candidate bundle lacks %s" % member)
            handle = archive.extractfile(entry)
            if handle is None:
                raise ValueError(
                    "candidate bundle lacks %s" % member)
            blob = handle.read()
            got = hashlib.sha256(blob).hexdigest()
            if got != want:
                raise ValueError(
                    "sealed member drift on extract: %s" % member)
            name = names[member]
            dst = os.path.join(work, name)
            with open(dst, "wb") as out_handle:
                out_handle.write(blob)
            os.chmod(dst, 0o755 if name == "memveil" else 0o644)
            out[name] = {"path": dst, "sha256": got}
    finally:
        archive.close()
    # The committed Aya fixtures must name the same object
    # bytes the seal carries; either side drifting refuses.
    for channel, fixture in (
            ("lifecycle", "swiotlb_lifecycle.bpf.o"),
            ("copy", "swiotlb_copy.bpf.o")):
        path = os.path.join(repo, "tests", "vm", "fixtures",
                            "aya", fixture)
        try:
            blob = open(path, "rb").read()
        except OSError as exc:
            raise ValueError("aya fixture unreadable %s: %s"
                             % (fixture, exc))
        if hashlib.sha256(blob).hexdigest() != out[
                {"lifecycle": "lifecycle.bpf.o",
                 "copy": "copy.bpf.o"}[channel]][
                "sha256"]:
            raise ValueError("aya fixture drift: %s" % fixture)
    try:
        with open(out["profile.json"]["path"]) as handle:
            profile_doc = json.load(handle)
    except (OSError, ValueError) as exc:
        raise ValueError("sealed profile unreadable: %s" % exc)
    profile_id = profile_doc.get("profile_id")
    if not profile_id or not isinstance(profile_id, str):
        raise ValueError("sealed profile lacks a profile id")
    candidate["files"][seal.BINARY_MEMBER] = binary_sha
    candidate["files"][seal.PROFILE_MEMBER] = profile_sha
    guest_oracle.verify_fixture()
    return {
        "binary": out["memveil"],
        "lc": out["lifecycle.bpf.o"],
        "cp": out["copy.bpf.o"],
        "profile": {"path": out["profile.json"]["path"],
                    "sha256": profile_sha,
                    "profile_id": profile_id},
        "candidate": candidate,
        "oracle": {
            "ko": guest_oracle.FIXTURE_KO,
            "ko_sha256": guest_oracle.KO_SHA256,
            "ko_vermagic": guest_oracle.GUEST_VERMAGIC,
            "btf_sha256": guest_oracle.GUEST_BTF_SHA256,
            "guest_release": guest_oracle.GUEST_RELEASE,
        },
        "guest": guest_binding(repo),
    }


def write_input_manifest(path, inputs, consumer, argv,
                         runner_commit, guest_inputs=None):
    """Write the held-open input manifest binding every byte.

    guest_inputs maps the held-open case to its staged
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
        "seal": seal.SEAL_LABEL,
        "runner_commit": runner_commit,
        "runner_argv": list(argv),
        "cases": [CASE],
        "consumer": {
            "binary_sha256": consumer["sha256"],
            "build": consumer["build"],
        },
        "binary": {"path": inputs["binary"]["path"],
                   "sha256": inputs["binary"]["sha256"]},
        "objects": {
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
    if manifest.get("seal") != seal.SEAL_LABEL:
        return ["manifest seal %r" % (manifest.get("seal"),)]
    for field in ("runner_commit", "runner_argv", "cases",
                  "consumer", "binary", "objects",
                  "guest_inputs", "profile",
                  "candidate", "oracle", "guest"):
        if field not in manifest:
            bad.append("manifest lacks %s" % field)
    if bad:
        return sorted(bad)
    for field in ("consumer", "binary", "objects",
                  "guest_inputs", "profile",
                  "candidate", "oracle", "guest"):
        if not isinstance(manifest.get(field), dict):
            bad.append("manifest %s is not a mapping" % field)
    if not isinstance(manifest.get("cases"), list):
        bad.append("manifest cases is not a list")
    if bad:
        return sorted(bad)
    cases = manifest.get("cases", [])
    if cases != [CASE]:
        bad.append("manifest cases %r" % (cases,))
    if consumer_path is not None:
        try:
            got = sha_file(consumer_path)
        except OSError as exc:
            return ["consumer unreadable: %s" % exc]
        if got != manifest["consumer"].get("binary_sha256"):
            bad.append("consumer digest mismatch")
    blobs = [("binary", manifest["binary"])]
    for channel in ("lc", "cp"):
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
    want = {"lc": seal.LC_SHA256, "cp": seal.CP_SHA256}
    for channel, digest in want.items():
        if manifest["objects"].get(channel, {}).get("sha256") \
                != digest:
            bad.append("%s object is not the sealed %s bytes"
                       % (channel, seal.SEAL_LABEL))
    candidate = manifest.get("candidate", {})
    files = candidate.get("files", {})
    if manifest["binary"].get("sha256") != files.get(
            seal.BINARY_MEMBER):
        bad.append("binary is not the sealed candidate bytes")
    if manifest["profile"].get("sha256") != files.get(
            seal.PROFILE_MEMBER):
        bad.append("profile is not the sealed candidate bytes")
    for member, channel in (
            ("bpf/swiotlb_lifecycle.bpf.o", "lc"),
            ("bpf/swiotlb_copy.bpf.o", "cp")):
        if manifest["objects"].get(channel, {}).get("sha256") \
                != files.get(member):
            bad.append("%s object differs from the seal"
                       % channel)
    if candidate.get("source", {}).get("commit") \
            != seal.SOURCE_COMMIT:
        bad.append("candidate source drift")
    if candidate.get("source", {}).get("tree") \
            != seal.SOURCE_TREE:
        bad.append("candidate source tree drift")
    if candidate.get("bundle_manifest_sha256") \
            != seal.BUNDLE_MANIFEST_SHA256:
        bad.append("candidate bundle manifest drift")
    if candidate.get("bundle", {}).get("sha256") \
            != seal.BUNDLE_SHA256:
        bad.append("candidate bundle drift")
    if str(candidate.get("bundle", {}).get("size")) \
            != str(seal.BUNDLE_SIZE):
        bad.append("candidate bundle size drift")
    if not manifest["profile"].get("profile_id") \
            or not isinstance(
                manifest["profile"].get("profile_id"), str):
        bad.append("profile id missing")
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
    entry = staged.get(CASE, {})
    if not isinstance(entry, dict) \
            or entry.get("file") != GUEST_INPUTS_FILE:
        bad.append("guest inputs lack a staged doc "
                   "for %s" % CASE)
    else:
        path = entry.get("path", "")
        try:
            got = sha_file(path)
        except OSError:
            bad.append("guest inputs doc unreadable for "
                       "%s: %s" % (CASE, path))
        else:
            if got != entry.get("sha256"):
                bad.append("guest inputs doc bytes differ "
                           "from manifest for %s" % CASE)
    for case in sorted(staged):
        if case != CASE:
            bad.append("guest inputs stage unknown case "
                       "%r" % (case,))
    return sorted(bad)
