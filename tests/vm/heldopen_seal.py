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

# Retained seal roots (dist/retained-39f4a227.../).
CANDIDATE_SHA256 = "39f4a22721dba8a6dfab751add6067deb7874689" \
    "87936485daa954ffe8eaf51d"
CANDIDATE_SCHEMA = "memveil-candidate/2"
SOURCE_COMMIT = "3a3d6cb8c8acc1295efdff6df44f2d89d327cc9c"
SOURCE_TREE = "25d906845f211b8ceb9873a0cbf2949d4a566bb9"
BUNDLE_MANIFEST_SHA256 = "d2f768990ac3d9150bcb660e38be4ac7a8e09134" \
    "3fbcd6aafaf2874065ee653e"
BUNDLE_SHA256 = "96f8dac7dcad44a4eb2f410f0cbbb69eb3204c17" \
    "3c9496cb44e3f87b16a15cc5"
BUNDLE_SIZE = 1803786

# Human label for receipts and probe output: the retained
# seal's candidate ID, single-sourced with the manifest
# digest above (a re-seal rebinds it with no edit here).
# The logic never branches on it: only the digests bind bytes.
SEAL_LABEL = CANDIDATE_SHA256

# Sealed BPF members. Seal verification covers all three;
# the leg loads the lifecycle/copy pair only (the attempt
# object is seal-verified, never extracted).
LC_SHA256 = "ad69cf0587597a1a8c14048dbb5f1256a604bf20" \
    "cc8d9f092d8c7b658c41f8e9"
CP_SHA256 = "29959dcbf9cc4cb40b9813cddf686d4118b0528f" \
    "29a8edec070504e1265350f8"
ATTEMPT_SHA256 = "8ee4903f6de717d013ae797e7963fefdb28549f4" \
    "ee04e3c5d4544a8e9de61d6a"

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
