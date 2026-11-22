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

Today it names the retained C9 seal: offline proof runs
against the retained C9 bytes. At the next seal these
values are replaced with the new seal's values — a
pin-file change, no logic edits. Re-pin procedure: swap
the constants below from the new seal's candidate
manifest (manifest digest, source commit/tree, bundle
manifest digest, bundle digest/size, member digests),
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
(heldopen_seal) with the same swap shape.
"""

# Retained seal manifest digest (sha256 of the sealed
# candidate.json bytes) and manifest schema.
CANDIDATE_SHA256 = "ac2503a3ef4269826ae3f9512ca2402d45e767" \
    "be2601c2893e812ebb6df929a7"
CANDIDATE_SCHEMA = "memveil-candidate/2"

# Sealed source identity (manifest "source" section).
SOURCE_COMMIT = "1af6cc9a912a38c8b2cb61da14749fbf1f628659"
SOURCE_TREE = "ac316ebc57a7b9d1aaf91bfcac8b1de410a6f614"

# Sealed bundle (tarball bytes, size, inner manifest).
BUNDLE_MANIFEST_SHA256 = "b2ba73f2d2ad02c8957171c08e4fbf4a9e689" \
    "5bec0a7d3074ad5c687e07ad820"
BUNDLE_SHA256 = "389f1d358e9eb8896c6033ec9ce18f74a1adda10d" \
    "2502f4a9e2d7f2943cb05ea"
BUNDLE_SIZE = 1797674

# Sealed BPF members (sha256 of the object bytes).
LC_SHA256 = "32f6a353779778981e727f311fe5d1b2c21fc92ae" \
    "9918765f86bc4f81f58df34"
CP_SHA256 = "526a6726e24f7725a0e88e28d6994f0475a1589c3de10" \
    "c7ebef703a03dfa73e8"
ATTEMPT_SHA256 = "ded931289c83713f62cdb5479fbf8aab03fe344d" \
    "91a91bdeeee7e76f106979eb"

# Sealed executable member.
BINARY_SHA256 = "df6b37665220adf72ccc5dd29a36bcd9e91165d0" \
    "d814de13c6ce5008c5532d7f"

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
