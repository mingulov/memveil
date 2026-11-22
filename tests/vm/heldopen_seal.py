#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Seal pins for the L6 held-open port.

The held-open leg executes the sealed candidate's
lifecycle/copy objects, the sealed executable for its
report step, and the seal-bound 7.0 reference profile.
This file is the ONLY place that names which seal those
bytes come from.

Today it names C9: offline proof runs against the
retained C9 bytes. At the next seal these values are
replaced with the new seal's values — a pin-file change,
no logic edits. Re-pin procedure: swap the constants below,
refresh the Aya fixture via its README procedure, and re-run
the probe-seal check.

Seal-independent pins live with their owners and are NOT
re-pinned at seal: the pinned guest row (battery_core:
VNG_TAG, VMLINUZ_SHA256, MODULES_MANIFEST_SHA256,
EXPECT_RELEASE), the oracle fixture (guest_oracle),
and the attach grammar (heldopen_guest LC_SITES/CP_SITES,
AST-equal to the battery's).
"""

# Human label for receipts and probe output. The logic
# never branches on it: only the digests below bind bytes.
SEAL_LABEL = "C9"

# Retained C9 seal roots (dist/retained-ac2503a3.../).
CANDIDATE_SHA256 = "ac2503a3ef4269826ae3f9512ca2402d45e767be2601c289" \
    "3e812ebb6df929a7"
CANDIDATE_SCHEMA = "memveil-candidate/2"
SOURCE_COMMIT = "1af6cc9a912a38c8b2cb61da14749fbf1f628659"
SOURCE_TREE = "ac316ebc57a7b9d1aaf91bfcac8b1de410a6f614"
BUNDLE_MANIFEST_SHA256 = "b2ba73f2d2ad02c8957171c08e4fbf4a9e6895bec0a7d3074" \
    "ad5c687e07ad820"
BUNDLE_SHA256 = "389f1d358e9eb8896c6033ec9ce18f74a1adda10d2502f4a9e2d7f294" \
    "3cb05ea"
BUNDLE_SIZE = 1797674

# Sealed BPF members. Seal verification covers all three;
# the leg loads the lifecycle/copy pair only (the attempt
# object is seal-verified, never extracted).
LC_SHA256 = "32f6a353779778981e727f311fe5d1b2c21fc92ae9918765f86bc4f81f58df34"
CP_SHA256 = "526a6726e24f7725a0e88e28d6994f0475a1589c3de10c7ebef703a03dfa73e8"
ATTEMPT_SHA256 = "ded931289c83713f62cdb5479fbf8aab03fe344d91a91bdeeee7e76f106979eb"

# Seal bundle members the leg extracts. Their digests are
# read from the verified seal (inner manifest), never
# pinned here: the manifest digest above already binds
# them, so a re-seal rebinds them with no edit here.
BINARY_MEMBER = "bin/memveil"
PROFILE_MEMBER = "profiles/linux-x86_64-7.0-reference.json"


def candidate_pins():
    """Pin dict for stress_core.verify_candidate_binding."""
    return {
        "candidate_sha256": CANDIDATE_SHA256,
        "schema": CANDIDATE_SCHEMA,
        "source_commit": SOURCE_COMMIT,
        "source_tree": SOURCE_TREE,
        "bundle_manifest_sha256": BUNDLE_MANIFEST_SHA256,
        "files": {
            "bpf/swiotlb_lifecycle.bpf.o": LC_SHA256,
            "bpf/swiotlb_copy.bpf.o": CP_SHA256,
            "bpf/swiotlb_attempt.bpf.o": ATTEMPT_SHA256,
        },
        "bundle_sha256": BUNDLE_SHA256,
        "bundle_size": BUNDLE_SIZE,
    }
