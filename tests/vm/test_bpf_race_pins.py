#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Host-side pins for the Q25-C6 identity-race fixes.

The lifecycle and copy probes' race behavior is qualified
by the multi-CPU VM stress gate
(tests/vm/test_identity_races.py), which needs a trusted
runner. These pins run on every host and fail closed if
the fixed semantics silently revert: exist-only generation
insert, delete-own-generation unmap, and an avalanched
call id. White-box by design: the flags are the fix.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

REPO = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LIFECYCLE = os.path.join(
    REPO, "bpf", "programs", "swiotlb_lifecycle.bpf.c")
COPY = os.path.join(
    REPO, "bpf", "programs", "swiotlb_copy.bpf.c")


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def test_gen_insert_is_exist_only():
    src = read(LIFECYCLE)
    assert re.search(
        r"bpf_map_update_elem\(&mv_gen_table, key, &gen,\s*"
        r"BPF_NOEXIST\)",
        src), "gen claim has no exist-only insert"
    assert not re.search(
        r"bpf_map_update_elem\(&mv_gen_table[^)]*BPF_ANY\)",
        src), "gen_table still takes BPF_ANY; concurrent " \
        "same-key maps would overwrite"


def test_gen_insert_reclaims_tombstones():
    # A failed delete leaves a zero tombstone behind; with
    # exist-only insert the map path must reclaim it (BPF_EXIST
    # update) instead of stranding the key unassignable.
    src = read(LIFECYCLE)
    assert "BPF_NOEXIST" in src, "insert is not exist-only"
    assert re.search(
        r"EEXIST[\s\S]{0,800}BPF_EXIST", src), \
        "no tombstone-reclaim path after EEXIST"


def test_unmap_deletes_own_generation():
    # Lookup-then-delete can remove a newer generation; the
    # unmap path must tombstone only the generation it read.
    src = read(LIFECYCLE)
    assert re.search(
        r"BPF_PROG\(mv_unmap[\s\S]*?"
        r"__sync_val_compare_and_swap\(slot", src), \
        "unmap has no compare-and-swap tombstone on its slot"


def test_lost_map_cleans_own_generation():
    # The lost-record cleanup must not delete a newer
    # generation that won the key after our insert.
    src = read(LIFECYCLE)
    assert re.search(
        r"BPF_PROG\(mv_map_result[\s\S]*?"
        r"__sync_val_compare_and_swap\(slot", src), \
        "map cleanup has no compare-and-swap on its slot"


def test_call_id_avalanches():
    # The XOR call id collides systematically; the fixed id
    # avalanches all three inputs (splitmix64 finalizer).
    src = read(COPY)
    m = re.search(
        r"static __always_inline __u64 mv_call_id\("
        r"[\s\S]*?\n\}\n",
        src)
    assert m, "mv_call_id not found"
    body = m.group(0)
    assert "0xBF58476D1CE4E5B9" in body, \
        "call id lacks the avalanche mixer"
    assert "tlb_addr ^ (size" not in body, \
        "call id still uses the plain XOR shape"
