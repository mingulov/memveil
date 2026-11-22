#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared core for the scenario-battery runner.

Ports the blocked scenario-battery legs onto the reviewed
test-only Rust consumer (tests/vm/stress-consumer/) and the
guest-targeted oracle fixture: the consumer legs
(matrix/copy/canonical/saturation/stop/skipsync) drive the
same consumer binary with digest-pinned C9 objects, while the
record legs (faults/record3) run the sealed C9 record
directly with the bound reference profile and no bridge.

This module binds every executed byte (C9 seal, objects,
oracle fixture, pinned guest kernel, profile), writes and
re-verifies the battery input manifest, and judges battery
legs with the existing battery predicates plus the two
battery-only additions: per-channel loss reconcile for the
faults leg and the standalone skip-sync judge. All judging
is pure and unit-tested on synthetic logs; live boots stay
in the runner.
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import tarfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "stress-consumer"))

import battery_guest  # noqa: E402
from consume import (check_conservation, check_oracle_script,  # noqa: E402
                     compare_scripted, parse_consume_file,
                     parse_oracle_log)
import guest_oracle  # noqa: E402
import stress_core as core  # noqa: E402

SCHEMA = "memveil-battery-inputs/1"

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
GUEST_INPUTS_SCHEMA = "memveil-battery-guest-inputs/1"

# The only guest release this battery admits, single-sourced
# from the guest flow. The oracle fixture loads only there,
# so the host pins below must all name it too.
EXPECT_RELEASE = battery_guest.EXPECT_RELEASE

# Pinned guest kernel, mirrored from the frozen
# tests/vm/kernels.lock.json row "7.0" (archive kind): the vng
# version tag boots it, the vmlinuz sha and the modules
# manifest sha verify its cache before any boot.
VNG_TAG = "v7.0.14"
VMLINUZ_SHA256 = "3d3d50d77364ff616ddeae0508c68f74501afdee9" \
    "679682ce3bf59edba5b4aca"
MODULES_MANIFEST_SHA256 = "921ffc5864bff7d52b128f907d8f439" \
    "9e422f773f4f66e7798297b6f9bf5ffdb"

# Bound test profile for the record legs: the shipped
# 7.0-reference doc, digest-pinned. Record admits all three
# channels under it through live-interface verification on
# the pinned guest; the decision string below is what the
# ported record judges expect instead of the retired
# record3-ephemeral mint.
PROFILE_REL = os.path.join(
    "profiles", "linux-x86_64-7.0-reference.json")
PROFILE_SHA256 = "9cce54cd23d6310bf617cc3689045f134" \
    "748e9806d9c397cad5c5cc0a2523a27"
PROFILE_ID = "linux-x86_64-7.0-reference"
PROFILE_DECISION = ("candidate linux-x86_64-7.0-reference: "
                    "live interfaces verified "
                    "(profile unvalidated)")

# Saturation test objects: separately hashed 4 KiB
# lifecycle/copy fixtures plus an explicit test layout in the
# consumer loader. Bound: the fixtures carry the same probes
# with 4 KiB rings, and the saturation guest flow and judges
# consume them by digest. Only these two constants plus the
# loader gate name the artifact.
TEST_LC_SHA256 = "6c340a485951d18b8302703e815df70f" \
    "41120408c645a1901ab62efa2f6133f9"
TEST_CP_SHA256 = "c5eed61a8632a0df53deee45bd2968b6" \
    "53e2c7f4a162141135e0fa82827080f9"
TEST_LC_REL = os.path.join(
    "tests", "vm", "fixtures", "aya-test",
    "swiotlb_lifecycle-test.bpf.o")
TEST_CP_REL = os.path.join(
    "tests", "vm", "fixtures", "aya-test",
    "swiotlb_copy-test.bpf.o")

# Attach grammar shared with the retired legs
# (tests/vm/guest_lifecycle.py) and the guest flow here.
LC_SITES = battery_guest.LC_SITES
CP_SITES = battery_guest.CP_SITES

CASES = ("matrix", "copy", "canonical-c", "canonical-e",
         "saturation", "stop", "faults", "record3",
         "skipsync")
CASE_TIMEOUTS = {
    "matrix": 900,
    "copy": 900,
    "canonical-c": 900,
    "canonical-e": 900,
    "saturation": 900,
    "stop": 1200,
    "faults": 1500,
    "record3": 900,
    "skipsync": 900,
}
# Faults floods the pcnet path during attach, so it needs
# the full-machine network boot; every other case boots the
# default microvm path.
CASE_NETWORK = {
    "matrix": False,
    "copy": False,
    "canonical-c": False,
    "canonical-e": False,
    "saturation": False,
    "stop": False,
    "faults": True,
    "record3": False,
    "skipsync": False,
}

# Detail-loss grammar from the product formatter
# (src/capture/collector.rs detail_reason_known plus the
# channel_loss_suffix triple): the head word is lowercase
# (first byte 0x64), then nine pooled buckets in fixed
# order summing to the head count, then one per-channel
# submit/malformed/dropped triple per attached channel.
LOSS_BUCKETS = ("submit_fail", "malformed", "dropped",
                "recursion_missed", "size_omitted",
                "duration_omitted", "signal_omitted",
                "rejected", "write_failed")
CHANNELS = ("attempt", "lifecycle", "copy")
# Product event kinds per transport channel.
CHANNEL_KINDS = {
    "attempt": ("bounce_attempt",),
    "lifecycle": ("map_result", "unmap"),
    "copy": ("sync_request", "copy"),
}


def sha_file(path):
    """SHA-256 of a file, streamed."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1048576), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git_head(repo):
    """Full commit of the checkout, or refusal text."""
    proc = subprocess.run(
        ["git", "-C", repo, "rev-parse", "HEAD"],
        capture_output=True, text=True, timeout=30)
    if proc.returncode != 0:
        raise ValueError("cannot read runner commit: %s"
                         % proc.stderr.strip())
    return proc.stdout.strip()


def profile_pins(repo):
    """Digest pins for the bound test profile doc."""
    path = os.path.join(repo, PROFILE_REL)
    try:
        with open(path) as handle:
            doc = json.load(handle)
    except (OSError, ValueError) as exc:
        raise ValueError("bound profile unreadable: %s" % exc)
    if doc.get("profile_id") != PROFILE_ID:
        raise ValueError("bound profile id drift: %r"
                         % doc.get("profile_id"))
    digest = sha_file(path)
    if digest != PROFILE_SHA256:
        raise ValueError("bound profile digest drift: %s..."
                         % digest[:16])
    return {"path": path, "sha256": digest,
            "profile_id": doc["profile_id"]}


def pinned_guest_entry(repo):
    """The frozen kernels.lock.json row this battery boots."""
    path = os.path.join(repo, "tests", "vm", "kernels.lock.json")
    try:
        with open(path) as handle:
            lock = json.load(handle)
    except (OSError, ValueError) as exc:
        raise ValueError("kernel lock unreadable: %s" % exc)
    for entry in lock.get("kernels", []):
        if entry.get("id") == "7.0":
            return entry
    raise ValueError("kernel lock lacks row 7.0")


def guest_binding(repo):
    """Guest-kernel binding cross-checked against the lock."""
    entry = pinned_guest_entry(repo)
    source = entry.get("source", {})
    binding = {
        "row": "7.0",
        "vng_tag": source.get("vng_version"),
        "release": entry.get("release"),
        "vmlinuz_sha256": source.get("vmlinuz_sha256"),
        "modules_manifest_sha256": source.get(
            "modules_manifest_sha256"),
    }
    if binding["vng_tag"] != VNG_TAG:
        raise ValueError("guest vng tag drift: %r"
                         % binding["vng_tag"])
    if binding["release"] != EXPECT_RELEASE:
        raise ValueError("guest release drift: %r"
                         % binding["release"])
    if binding["vmlinuz_sha256"] != VMLINUZ_SHA256:
        raise ValueError("guest vmlinuz pin drift")
    if binding["modules_manifest_sha256"] \
            != MODULES_MANIFEST_SHA256:
        raise ValueError("guest modules pin drift")
    return binding


def materialize(repo, work, candidate_path, bundle_path):
    """Write the sealed C9 bytes under work, verified.

    Verifies the explicit candidate seal (manifest digest,
    source, bundle bytes, inner manifest, all three BPF
    member hashes), then extracts the sealed binary plus
    the three objects and the bound profile into the run
    work dir. The objects are cross-checked byte-equal
    with the committed Aya fixtures. Returns the input
    dict the manifest carries. Any drift refuses.
    """
    os.makedirs(work, exist_ok=True)
    candidate = core.verify_candidate_binding(
        candidate_path, bundle_path)
    # The binary sha rides in the verified manifest next to
    # the object pins; re-hash after reading so a swapped
    # file refuses instead of rebinding silently.
    try:
        with open(candidate_path) as handle:
            manifest_doc = json.load(handle)
    except (OSError, ValueError) as exc:
        raise ValueError("candidate manifest unreadable: %s"
                         % exc)
    if sha_file(candidate_path) != core.C9_CANDIDATE_SHA:
        raise ValueError("candidate manifest drift on reread")
    try:
        binary_sha = manifest_doc["files"]["bin/memveil"]
    except KeyError:
        raise ValueError("candidate seal lacks bin/memveil")
    candidate["files"]["bin/memveil"] = binary_sha
    files = candidate["files"]
    member_shas = {
        "bin/memveil": files["bin/memveil"],
        "bpf/swiotlb_attempt.bpf.o":
            files["bpf/swiotlb_attempt.bpf.o"],
        "bpf/swiotlb_lifecycle.bpf.o":
            files["bpf/swiotlb_lifecycle.bpf.o"],
        "bpf/swiotlb_copy.bpf.o":
            files["bpf/swiotlb_copy.bpf.o"],
    }
    try:
        archive = tarfile.open(bundle_path, "r:gz")
    except (tarfile.TarError, OSError) as exc:
        raise ValueError("candidate bundle unreadable: %s" % exc)
    try:
        members = {m.name: m for m in archive.getmembers()
                   if m.isfile()}
        out = {}
        for member, want in sorted(member_shas.items()):
            entry = members.get("bundle/" + member)
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
            name = {"bin/memveil": "memveil",
                    "bpf/swiotlb_attempt.bpf.o": "attempt.bpf.o",
                    "bpf/swiotlb_lifecycle.bpf.o":
                        "lifecycle.bpf.o",
                    "bpf/swiotlb_copy.bpf.o": "copy.bpf.o"}[member]
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
            ("copy", "swiotlb_copy.bpf.o"),
            ("attempt", "swiotlb_attempt.bpf.o")):
        path = os.path.join(repo, "tests", "vm", "fixtures",
                            "aya", fixture)
        try:
            blob = open(path, "rb").read()
        except OSError as exc:
            raise ValueError("aya fixture unreadable %s: %s"
                             % (fixture, exc))
        if hashlib.sha256(blob).hexdigest() != out[
                {"lifecycle": "lifecycle.bpf.o",
                 "copy": "copy.bpf.o",
                 "attempt": "attempt.bpf.o"}[channel]][
                "sha256"]:
            raise ValueError("aya fixture drift: %s" % fixture)
    pins = profile_pins(repo)
    prof_dir = os.path.join(work, "profiles")
    os.makedirs(prof_dir, exist_ok=True)
    prof_dst = os.path.join(prof_dir, "battery-profile.json")
    with open(prof_dst, "wb") as handle:
        handle.write(open(pins["path"], "rb").read())
    # Record loads its profiles dir for the scan order even
    # with an explicit --profile: the dir carries a manifest
    # naming exactly the bound bytes.
    with open(os.path.join(prof_dir, "manifest.txt"),
              "w") as handle:
        handle.write("battery-profile.json\n")
    guest_oracle.verify_fixture()
    return {
        "binary": out["memveil"],
        "attempt": out["attempt.bpf.o"],
        "lc": out["lifecycle.bpf.o"],
        "cp": out["copy.bpf.o"],
        "profile": {"path": prof_dst,
                    "sha256": pins["sha256"],
                    "profile_id": pins["profile_id"]},
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


def materialize_test_objects(repo, work):
    """Stage the bound saturation pair under work, verified.

    Reads the committed 4 KiB fixtures, refuses unless their
    bytes equal the TEST_*_SHA256 pins, and copies them into
    the run work dir (which the guest resolves identically).
    Returns {lc/cp: {path, sha256}} for the manifest writer
    and the staged guest-inputs docs. Any drift refuses.
    """
    os.makedirs(work, exist_ok=True)
    pair = {}
    for channel, rel, want in (
            ("lc", TEST_LC_REL, TEST_LC_SHA256),
            ("cp", TEST_CP_REL, TEST_CP_SHA256)):
        src = os.path.join(repo, rel)
        try:
            with open(src, "rb") as handle:
                blob = handle.read()
        except OSError as exc:
            raise ValueError("saturation test object unreadable "
                             "%s: %s" % (rel, exc))
        got = hashlib.sha256(blob).hexdigest()
        if got != want:
            raise ValueError("saturation test object drift: %s"
                             % rel)
        dst = os.path.join(work, os.path.basename(rel))
        with open(dst, "wb") as handle:
            handle.write(blob)
        os.chmod(dst, 0o644)
        pair[channel] = {"path": dst, "sha256": got}
    return pair


def write_input_manifest(path, inputs, consumer, cases, argv,
                         runner_commit, test_objects=None,
                         guest_inputs=None):
    """Write the battery input manifest binding every byte.

    test_objects names the bound saturation pair
    ({lc/cp: {path, sha256}}); without it the saturation
    case stays unbound and refuses. guest_inputs maps each
    listed case to the staged guest-inputs doc path for
    that case; the doc bytes are re-hashed at write time,
    so the manifest always stamps the exact bytes the
    guest must see. Bound bytes are re-hashed at write
    time, so the manifest always stamps measured bytes.
    """
    if test_objects is None:
        test_entry = {
            "bound": False,
            "reason": "saturation 4 KiB objects unbound "
                      "for this run (no staged test pair)",
        }
    else:
        test_entry = {"bound": True}
        for channel in ("lc", "cp"):
            entry = test_objects[channel]
            test_entry[channel] = {
                "path": entry["path"],
                "sha256": sha_file(entry["path"]),
            }
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
        "test_objects": test_entry,
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
                  "test_objects", "guest_inputs", "profile",
                  "candidate", "oracle", "guest"):
        if field not in manifest:
            bad.append("manifest lacks %s" % field)
    if bad:
        return sorted(bad)
    for field in ("consumer", "binary", "objects",
                  "test_objects", "guest_inputs", "profile",
                  "candidate", "oracle", "guest"):
        if not isinstance(manifest.get(field), dict):
            bad.append("manifest %s is not a mapping" % field)
    if not isinstance(manifest.get("cases"), list):
        bad.append("manifest cases is not a list")
    if bad:
        return sorted(bad)
    cases = manifest.get("cases", [])
    if not cases or any(c not in CASES for c in cases):
        bad.append("manifest cases %r" % (cases,))
    if len(set(cases)) != len(cases):
        bad.append("manifest cases repeat")
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
    want = {"attempt": core.C9_ATTEMPT_SHA,
            "lc": core.C9_LC_SHA, "cp": core.C9_CP_SHA}
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
            != core.C9_SOURCE_COMMIT:
        bad.append("candidate source drift")
    if candidate.get("bundle_manifest_sha256") \
            != core.C9_BUNDLE_MANIFEST_SHA:
        bad.append("candidate bundle manifest drift")
    if candidate.get("bundle", {}).get("sha256") \
            != core.C9_BUNDLE_SHA:
        bad.append("candidate bundle drift")
    if manifest["profile"].get("profile_id") != PROFILE_ID:
        bad.append("profile id drift")
    if manifest["profile"].get("sha256") != PROFILE_SHA256:
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
    test_objects = manifest.get("test_objects", {})
    if "saturation" in cases and test_objects.get("bound"):
        for channel in ("lc", "cp"):
            entry = test_objects.get(channel, {})
            path = entry.get("path", "")
            try:
                got = sha_file(path)
            except OSError:
                bad.append("saturation %s test object "
                           "unreadable: %s" % (channel, path))
                continue
            if got != entry.get("sha256"):
                bad.append("saturation %s test object bytes "
                           "differ from manifest" % channel)
    if "saturation" in cases and not test_objects.get("bound"):
        bad.append("saturation needs bound 4 KiB test "
                   "objects: unbound for this run")
    return sorted(bad)


# -- Loss grammar (strict product shapes) ---------------------

_LOSS_HEAD = re.compile(
    r"^detail loss (\d+) \("
    + r" ".join(r"%s=\((\d+)\)" % name
                for name in LOSS_BUCKETS)
    + r"\)$")
_LOSS_UNKNOWN = re.compile(
    r"^detail loss unknown \(([^;]*); known: "
    + r" ".join(r"%s=\(([^)]*)\)" % name
                for name in LOSS_BUCKETS)
    + r"\)$")
_CHANNEL_TRIPLE = re.compile(
    r"(attempt|lifecycle|copy):\(submit_fail=([0-9]+|"
    r"unavailable) malformed=([0-9]+|unavailable) "
    r"dropped=([0-9]+|unavailable)\)")


def parse_detail_loss(session):
    """Parse the detail quality into loss facts, strictly.

    Returns {"loss_count", "buckets", "channels", "unknown"}.
    "channels" maps each named channel to its
    submit/malformed/dropped triple (ints, or None per
    component when the product reports unavailable) and is
    None when the reason carries no channel suffix
    (attempt-only captures). Raises ValueError on any
    reason shape outside the known and unknown grammars.
    """
    try:
        quality = session["quality"]["detail"]
        loss_count = int(quality["loss_count"])
        reason = quality["reason"]
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("detail quality unreadable: %s" % exc)
    if not isinstance(reason, str):
        raise ValueError("Detail reason is not text")
    head, sep, suffix = reason.partition("; channels ")
    if not sep:
        channels = None
    else:
        found = _CHANNEL_TRIPLE.findall(suffix)
        # The suffix is exactly space-joined triples in
        # channel order; anything else is grammar drift.
        rebuilt = " ".join(
            "%s:(submit_fail=%s malformed=%s dropped=%s)"
            % triple for triple in found)
        if not found or rebuilt != suffix:
            raise ValueError(
                "channel loss grammar drift: %r"
                % suffix[:120])

        def num(text):
            return None if text == "unavailable" \
                else int(text)
        channels = {}
        for name, submit, malformed, dropped in found:
            if name in channels:
                raise ValueError(
                    "channel loss repeats %s" % name)
            channels[name] = {
                "submit_fail": num(submit),
                "malformed": num(malformed),
                "dropped": num(dropped),
            }
        if sorted(channels) not in (["attempt"],
                                    ["attempt", "copy"],
                                    ["attempt", "lifecycle"],
                                    ["attempt", "copy",
                                     "lifecycle"]):
            raise ValueError("channel loss set drift: %r"
                             % sorted(channels))
        order = [name for name, _, _, _ in found]
        if order != [name for name in CHANNELS
                     if name in channels]:
            raise ValueError("channel loss order drift: %r"
                             % (order,))
    match = _LOSS_HEAD.match(head)
    if match is not None:
        buckets = {name: int(match.group(i + 2)) for i, name
                   in enumerate(LOSS_BUCKETS)}
        if int(match.group(1)) != sum(buckets.values()):
            raise ValueError("Detail head count is not the "
                             "bucket sum")
        if loss_count != sum(buckets.values()):
            raise ValueError("loss_count %d is not the pooled "
                             "bucket sum %d"
                             % (loss_count,
                                sum(buckets.values())))
        return {"loss_count": loss_count, "buckets": buckets,
                "channels": channels, "unknown": False}
    match = _LOSS_UNKNOWN.match(head)
    if match is not None:
        if channels is not None:
            raise ValueError("unknown loss carries channels")
        return {"loss_count": loss_count,
                "buckets": None, "channels": None,
                "unknown": True,
                "cause": match.group(1)}
    raise ValueError("Detail reason grammar drift: %r"
                     % reason[:120])


def scripted_prefix_expectation(op_indices):
    """Expected probe classes for an explicit op set.

    Replicates the oracle module script rules per op (sizes
    cycle 512/1024/2048/4096, directions alternate
    TO/FROM, op 1 syncs twice): every listed op maps, syncs,
    and releases fully. A signal-cut judge bounds persisted
    records by the attempted set, which over-approximates
    the in-flight op and stays a sound upper bound.
    Returns class counts per transport channel.
    """
    counts = {"attempt": 0, "lifecycle": 0, "copy": 0}
    for i in sorted(op_indices):
        direction = 2 if i % 2 else 1
        counts["attempt"] += 1
        counts["lifecycle"] += 2
        syncs = 2 if i == 1 else 1
        # Sync requests (dev syncs plus one cpu sync) plus
        # copy records (map-time, per-sync for TO, release
        # for FROM) follow the scripted_expectation rule.
        counts["copy"] += 2 + syncs
        counts["copy"] += syncs if direction == 1 else 1
    return counts


def check_per_channel_loss(events, session, want, tag,
                           strict_total=True):
    """Reconcile recorded plus omitted loss per channel.

    want maps each transport channel (attempt/lifecycle/
    copy) to its predicted record count over the judged
    slice. Every channel's persisted count must stay at or
    under its prediction (a pooled sum alone would hide
    one channel over-counting while another under-counts),
    the pooled shortfall must equal the declared loss
    exactly when strict_total holds (full-script floods),
    and the per-channel transport triples must agree with
    the pooled buckets while staying within their own
    channel's shortfall. Unknown or unavailable loss
    refuses: undeclared gaps never reconcile. Returns a
    sorted reason list.
    """
    bad = []
    try:
        loss = parse_detail_loss(session)
    except ValueError as exc:
        return ["%s: %s" % (tag, exc)]
    if loss["unknown"]:
        return ["%s: detail loss unknown (%s): "
                "unreconciled" % (tag, loss["cause"])]
    persisted = {channel: 0 for channel in CHANNELS}
    for event in events:
        for channel, kinds in CHANNEL_KINDS.items():
            if event.get("kind") in kinds:
                persisted[channel] += 1
    for channel in CHANNELS:
        if persisted[channel] > want.get(channel, 0):
            bad.append("%s: %s persisted %d over predicted "
                       "%d" % (tag, channel,
                               persisted[channel],
                               want.get(channel, 0)))
    shortfalls = {channel: want.get(channel, 0)
                  - persisted[channel] for channel in CHANNELS}
    if strict_total and sum(shortfalls.values()) != \
            loss["loss_count"]:
        bad.append("%s: pooled shortfall %d != declared "
                   "loss %d"
                   % (tag, sum(shortfalls.values()),
                      loss["loss_count"]))
    channels = loss["channels"]
    if channels is None:
        return sorted(bad)
    for key in ("submit_fail", "malformed", "dropped"):
        parts = [channels[channel][key] for channel in
                 sorted(channels)]
        if any(v is None for v in parts):
            bad.append("%s: %s unavailable on a channel: "
                       "unreconciled" % (tag, key))
        elif sum(parts) != loss["buckets"][key]:
            bad.append("%s: channel %s sums %d != pooled %d"
                       % (tag, key, sum(parts),
                          loss["buckets"][key]))
    for channel, triple in sorted(channels.items()):
        parts = [triple[key] for key in
                 ("submit_fail", "malformed", "dropped")]
        if any(v is None for v in parts):
            continue
        if sum(parts) > shortfalls.get(channel, 0):
            bad.append("%s: %s declares %d channel loss "
                       "with only %d missing"
                       % (tag, channel, sum(parts),
                          shortfalls.get(channel, 0)))
    return sorted(bad)


# -- Skip-sync judge (L5) ------------------------------------

def judge_skipsync(lc_path, cp_path, oracle_path, tag):
    """Judge one directed skip-sync window.

    Requires the existing scripted predicates (exact
    oracle script, exact multisets, the flag predicate: all
    unmaps skip-marked at the covered inner unmap hook),
    then the skip-sync additions: every unmap pairs to its
    map by nonzero generation with an independent oracle
    release for the same mapping, TO_DEVICE controls carry
    no release copy, and FROM_DEVICE controls carry a
    fully verified release copy-back witness. An empty
    window, a flipped skip flag, or a missing release
    fails. Returns a sorted reason list.
    """
    bad = []
    try:
        lc, lc_sum = parse_consume_file(lc_path)
        cp, cp_sum = parse_consume_file(cp_path)
        ops_log, releases, complete = parse_oracle_log(
            oracle_path)
    except (ValueError, OSError) as exc:
        return ["%s: window files unreadable: %s" % (tag, exc)]
    bad += check_conservation(lc, lc_sum, tag + "-lc")
    bad += check_conservation(cp, cp_sum, tag + "-cp")
    if not lc and not cp:
        bad.append("%s: empty window observes nothing" % tag)
    if not ops_log:
        bad.append("%s: empty window runs no ops" % tag)
        return sorted(bad)
    bad += check_oracle_script(ops_log, releases, complete,
                               4, -1, tag)
    bad += compare_scripted(lc, cp, 4, -1, tag)
    # Generation pairing per op: scripted sizes are unique
    # per op, so the pairing is unambiguous, and each
    # unmap must carry its own map's nonzero generation
    # with an independent oracle release for the mapping.
    maps = {}
    for event in lc:
        if event["kind"] == 1:
            maps.setdefault(event["size"], []).append(event)
    unmaps = {}
    for event in lc:
        if event["kind"] == 2:
            unmaps.setdefault(event["size"], []).append(event)
    for i in sorted(ops_log):
        entry = ops_log[i]
        if entry.get("success") is not True:
            continue
        size = entry["mapped"]
        mapping = entry["mapping"]
        pair = maps.get(size, [])
        rel = unmaps.get(size, [])
        if len(pair) != 1 or len(rel) != 1:
            bad.append("%s: op %d size %d pairing lost "
                       "(maps %d unmaps %d)"
                       % (tag, i, size, len(pair), len(rel)))
            continue
        if pair[0]["gen"] == 0 or rel[0]["gen"] == 0:
            bad.append("%s: op %d unassigned generation"
                       % (tag, i))
        if pair[0]["gen"] != rel[0]["gen"]:
            bad.append("%s: op %d unmap gen %d != map gen "
                       "%d" % (tag, i, rel[0]["gen"],
                               pair[0]["gen"]))
        if mapping not in releases:
            bad.append("%s: op %d mapping %d never "
                       "released" % (tag, i, mapping))
    # Outer copy behavior across the skip/ordinary
    # controls: TO_DEVICE unmaps are the skip path (no
    # release copy), FROM_DEVICE unmaps are the ordinary
    # release (full witnessed copy-back).
    for i in sorted(ops_log):
        entry = ops_log[i]
        if entry.get("success") is not True:
            continue
        direction = 2 if i % 2 else 1
        kinds = [w["copy"] for w in
                 entry.get("witness", [])]
        if direction == 1:
            if "release" in kinds:
                bad.append("%s: op %d TO release copied "
                           "%d bytes on the skip path"
                           % (tag, i, entry["mapped"]))
        else:
            found = [w for w in entry.get("witness", [])
                     if w["copy"] == "release"]
            if len(found) != 1:
                bad.append("%s: op %d FROM wants 1 release "
                           "witness, got %d"
                           % (tag, i, len(found)))
            elif (found[0]["copied"],
                  found[0]["verified"]) != (entry["mapped"],
                                            entry["mapped"]):
                bad.append("%s: op %d FROM release witness "
                           "%r" % (tag, i, found[0]))
    return sorted(bad)
