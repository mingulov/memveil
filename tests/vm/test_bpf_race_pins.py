#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Host-side pins for the identity-race fixes.

The lifecycle and copy probes' race behavior is qualified
by the multi-CPU VM stress gate
(tests/vm/test_identity_races.py), which needs a trusted
runner. These pins run on every host and fail closed if
the fixed semantics silently revert: exist-only generation
insert, delete-own-generation unmap, and an avalanched
call id. White-box by design: the flags are the fix.
(Ported to the Rust probes at the cutover; the C-probe
originals retired with the C tree.)
"""

import os
import re

REPO = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LIFECYCLE = os.path.join(
    REPO, "crates", "ebpf", "src", "lifecycle.rs")
COPY = os.path.join(
    REPO, "crates", "ebpf", "src", "copy.rs")


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def test_gen_insert_is_exist_only():
    src = read(LIFECYCLE)
    assert re.search(
        r"MV_GEN_TABLE\.insert\(key, gen, BPF_NOEXIST as u64\)",
        src), "gen claim has no exist-only insert"
    assert "BPF_ANY" not in src, \
        "gen_table takes BPF_ANY; concurrent same-key maps " \
        "would overwrite"


def test_gen_insert_reclaims_tombstones():
    # A failed delete leaves a zero tombstone behind; with
    # exist-only insert the map path must reclaim it (BPF_EXIST
    # update) instead of stranding the key unassignable.
    src = read(LIFECYCLE)
    assert "BPF_NOEXIST" in src, "insert is not exist-only"
    assert re.search(
        r"fn mv_claim_gen[\s\S]{0,1200}BPF_EXIST", src), \
        "no tombstone-reclaim path in the claim function"


def test_unmap_deletes_own_generation():
    # Lookup-then-delete can remove a newer generation; the
    # unmap path must tombstone only the generation it read.
    src = read(LIFECYCLE)
    assert re.search(
        r"fn try_mv_unmap[\s\S]*?"
        r"count_cas\(slot, gen, 0\)", src), \
        "unmap has no compare-and-swap tombstone on its slot"


def test_lost_map_cleans_own_generation():
    # The lost-record cleanup must not delete a newer
    # generation that won the key after our insert.
    src = read(LIFECYCLE)
    m = re.search(
        r"fn mv_map_result[\s\S]*?fn try_mv_unmap", src)
    assert m, "mv_map_result region not found"
    assert "count_cas(slot, gen, 0)" in m.group(0), \
        "map cleanup has no compare-and-swap on its slot"


def test_call_id_avalanches():
    # The XOR call id collides systematically; the fixed id
    # avalanches all three inputs (splitmix64 finalizer).
    src = read(COPY)
    m = re.search(
        r"fn call_id\("
        r"[\s\S]*?\n\}\n",
        src)
    assert m, "call_id not found"
    body = m.group(0)
    flat = body.replace("_", "").lower()
    assert "0xbf58476d1ce4e5b9" in flat, \
        "call id lacks the avalanche mixer"
    assert "tlb_addr ^" not in body, \
        "call id still uses the plain XOR shape"
