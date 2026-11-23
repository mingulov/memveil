#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Seal pins for the L6 held-open port.

The held-open leg executes the sealed candidate's
lifecycle/copy objects, the sealed executable for its
report step, and the seal-bound 7.0 reference profile.
This file is the ONLY place that names which seal those
bytes come from.

Today it names the retained seal (see CANDIDATE_SHA256
below): offline proof runs against the retained bytes.
At the next seal these values are replaced with the new
seal's values — a pin-file change, no logic edits.
Re-pin procedure: swap the constants below, refresh the
Aya fixture via its README procedure, and re-run the
probe-seal check.

Seal-independent pins live with their owners and are NOT
re-pinned at seal: the pinned guest row (battery_core:
VNG_TAG, VMLINUZ_SHA256, MODULES_MANIFEST_SHA256,
EXPECT_RELEASE), the oracle fixture (guest_oracle),
and the attach grammar (heldopen_guest LC_SITES/CP_SITES,
AST-equal to the battery's).
"""

# Retained seal roots (dist/retained-08bdeaed.../).
CANDIDATE_SHA256 = "08bdeaed2e8646c28b1a6dda760ae9071f603816" \
    "ab8e219600cb465749b890c9"
CANDIDATE_SCHEMA = "memveil-candidate/2"
SOURCE_COMMIT = "bdf641c36addc345f3fb6d8bf925059c6f1fa714"
SOURCE_TREE = "cc4447b939ef5e6ef79637dd675a0a1476f224c0"
BUNDLE_MANIFEST_SHA256 = "e81f9a5518fb56341ede0526c7bf604ab5214619" \
    "f0bbd4e55271d6891a808870"
BUNDLE_SHA256 = "1421538887f8fc7673b5edcb55c6633ff6febec6" \
    "d21257a181fcab4cd20d863e"
BUNDLE_SIZE = 1826844

# Human label for receipts and probe output: the retained
# seal's candidate ID, single-sourced with the manifest
# digest above (a re-seal rebinds it with no edit here).
# The logic never branches on it: only the digests bind bytes.
SEAL_LABEL = CANDIDATE_SHA256

# Sealed BPF members. Seal verification covers all three;
# the leg loads the lifecycle/copy pair only (the attempt
# object is seal-verified, never extracted).
LC_SHA256 = "0cd5a0c9b961605f0c47fbcf0a5377080e5ca3f6" \
    "24d6c9860a57e816aff4527f"
CP_SHA256 = "daacd9950fec82d00c9dde5a33a7398d7e3c708d" \
    "557455ab93b521aa0cf94227"
ATTEMPT_SHA256 = "81ebd35c1450e905de1eaf2d23ea2827328a221a" \
    "a8eabf2b4ca4e2f4daa026b6"

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
