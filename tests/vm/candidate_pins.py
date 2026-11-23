#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Candidate seal pins for the repeat runners.

The stress (Q3/Q4), battery, late-attach, and faults
runners execute the sealed candidate's lifecycle/copy
objects (plus the attempt object, the sealed executable,
and the seal-bound reference profile where a leg needs
them). This file is the ONLY place that names which seal
those bytes come from: every guard in those runners reads
its expected values from here, and no other file in the
repeat path carries seal digests.

Today it names the retained seal (see CANDIDATE_SHA256
below): offline proof runs against the retained bytes.
At the next seal these values are replaced with the new
seal's values — a pin-file change, no logic edits.
Re-pin procedure: swap the constants below from the new
seal's candidate manifest (manifest digest, source
commit/tree, bundle manifest digest, bundle digest/size,
member digests),
refresh the Aya fixtures via their README procedure so
the committed bytes equal the new seal's objects, and
re-run the offline suites plus the seal-swap check
(`python3 tests/vm/test_seal_swap.py` from the repo
root). When
the new seal's profile member differs, the reviewed
profile doc moves with it (battery profile pin plus the
faults profile pin are a paired edit, enforced by the
pin cross-check test).

Seal-independent pins live with their owners and are NOT
re-pinned at seal: the pre-change baseline pair
(stress_core BASELINE_*), the pinned guest row
(battery_core VNG_TAG/VMLINUZ_SHA256/
MODULES_MANIFEST_SHA256/EXPECT_RELEASE), the oracle
fixture (guest_oracle), the saturation test objects
(battery_core TEST_*), and the attach grammar (guest
flows). The L6 held-open leg keeps its own pin file
(heldopen_seal) with the same swap shape. The scenario
runner is outside the repeat path and keeps its own
sealed-source and fixture-blob pins (tools/kernel-matrix,
mirrored by its offline test): swap them in the same
pass, from the same seal, or its staging legs refuse.
"""

import os
import tomllib

# Retained seal manifest digest (sha256 of the sealed
# candidate.json bytes) and manifest schema.
CANDIDATE_SHA256 = "08bdeaed2e8646c28b1a6dda760ae9071f603816" \
    "ab8e219600cb465749b890c9"
CANDIDATE_SCHEMA = "memveil-candidate/2"

# Sealed source identity (manifest "source" section).
SOURCE_COMMIT = "bdf641c36addc345f3fb6d8bf925059c6f1fa714"
SOURCE_TREE = "cc4447b939ef5e6ef79637dd675a0a1476f224c0"

# Sealed bundle (tarball bytes, size, inner manifest).
BUNDLE_MANIFEST_SHA256 = "e81f9a5518fb56341ede0526c7bf604ab5214619" \
    "f0bbd4e55271d6891a808870"
BUNDLE_SHA256 = "1421538887f8fc7673b5edcb55c6633ff6febec6" \
    "d21257a181fcab4cd20d863e"
BUNDLE_SIZE = 1826844

# Sealed BPF members (sha256 of the object bytes).
LC_SHA256 = "0cd5a0c9b961605f0c47fbcf0a5377080e5ca3f6" \
    "24d6c9860a57e816aff4527f"
CP_SHA256 = "daacd9950fec82d00c9dde5a33a7398d7e3c708d" \
    "557455ab93b521aa0cf94227"
ATTEMPT_SHA256 = "81ebd35c1450e905de1eaf2d23ea2827328a221a" \
    "a8eabf2b4ca4e2f4daa026b6"

# Sealed executable member.
BINARY_SHA256 = "6fa00bfba2bbff4aecd5b8185a6d736b7170f12f" \
    "be26754fd51b97750395275d"

# Sealed profile member. The bound profile doc is
# reviewed separately (battery_core.PROFILE_SHA256 names
# the checkout bytes); the faults gate requires the two
# to be byte-equal, and the pin cross-check test enforces
# the equality, so a seal whose profile member differs
# moves the reviewed doc as a paired edit.
PROFILE_SHA256 = "9cce54cd23d6310bf617cc3689045f134" \
    "748e9806d9c397cad5c5cc0a2523a27"

# Seal bundle member paths (schema, not pins).
LC_MEMBER = "bpf/swiotlb_lifecycle.bpf.o"
CP_MEMBER = "bpf/swiotlb_copy.bpf.o"
ATTEMPT_MEMBER = "bpf/swiotlb_attempt.bpf.o"
BINARY_MEMBER = "bin/memveil"
PROFILE_MEMBER = "profiles/linux-x86_64-7.0-reference.json"


def bpf_files():
    """The three sealed BPF member digests, as a fresh dict."""
    return {
        LC_MEMBER: LC_SHA256,
        CP_MEMBER: CP_SHA256,
        ATTEMPT_MEMBER: ATTEMPT_SHA256,
    }


def seal_files():
    """All five sealed member digests, as a fresh dict."""
    files = bpf_files()
    files[BINARY_MEMBER] = BINARY_SHA256
    files[PROFILE_MEMBER] = PROFILE_SHA256
    return files


def candidate_pins():
    """The pinned seal the stress/battery runners bind.

    Covers the manifest digest, schema, source and tree,
    the bundle size and hash, and the three BPF member
    hashes (binary/profile members ride in the verified
    manifest next to these pins where a leg needs them).
    """
    return {
        "candidate_sha256": CANDIDATE_SHA256,
        "schema": CANDIDATE_SCHEMA,
        "source_commit": SOURCE_COMMIT,
        "source_tree": SOURCE_TREE,
        "bundle_manifest_sha256": BUNDLE_MANIFEST_SHA256,
        "files": bpf_files(),
        "bundle_sha256": BUNDLE_SHA256,
        "bundle_size": BUNDLE_SIZE,
    }


def seal_pins():
    """The pinned seal the faults gate binds, as a pins dict.

    Same seal as candidate_pins, plus the executable and
    bound-profile member hashes this gate runs.
    """
    pins = candidate_pins()
    pins["files"] = seal_files()
    return pins


def dist_bundle_tarball(repo):
    """The checkout dist/ seal's bundle tarball path.

    The packager tags the default bundle memveil-<version>
    from the built binary (which reports Cargo.toml), so
    the default resolves from the same manifest instead
    of duplicating the version: a custom --tag still
    needs an explicit path, like before.
    """
    with open(os.path.join(repo, "Cargo.toml"), "rb") as handle:
        version = tomllib.load(handle)["package"]["version"]
    return os.path.join(
        repo, "dist", "memveil-%s.tar.gz" % version)
