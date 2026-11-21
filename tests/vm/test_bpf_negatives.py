#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Unarmed self-tests for the negative producer.

No boots, no privileged calls, no network: rebuilds the four
negative objects twice (determinism), round-trips the
run-input manifest, reproduces the baseline bytes (positive
control), checks loader-bytes path stability, and re-runs
every offline proof. Slow by design (~6 minutes of
pinned-toolchain builds); run alone, not as part of a fast
gate.
"""

import json
import os
import shutil
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "negatives"))

import proof
import producer


@pytest.fixture(scope="module")
def built():
    """Fresh full producer build; map name to sha256."""
    root = producer.repo_root()
    _, shas, mutant_src = producer.build_all(root)
    assert set(shas) == set(producer.NAMES)
    return root, shas, mutant_src


def test_producer_rebuild_identical(built):
    """Rebuild twice: identical shas for all four."""
    root, first, _ = built
    _, second, _ = producer.build_all(root)
    assert second == first


def test_manifest_roundtrip(built, tmp_path):
    """A fresh manifest verifies against the staged bytes."""
    root, shas, mutant_src = built
    versions = producer.check_toolchain()
    path = str(tmp_path / "roundtrip-manifest.json")
    producer.write_manifest(root, versions, shas, mutant_src,
                            path=path)
    assert producer.verify_manifest(root, path) == []
    with open(path, "r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    assert set(manifest["objects"]) == set(producer.NAMES)
    assert manifest["producer"]["source_sha256"] == \
        producer.producer_source_sha()


def test_committed_manifest_verifies(built):
    """The committed manifest (when present) verifies."""
    root, _, _ = built
    path = producer.manifest_path()
    if not os.path.isfile(path):
        pytest.skip("no committed run-input-manifest.json")
    assert producer.verify_manifest(root, path) == []


def test_base_reproduction(built, tmp_path):
    """Positive control: the recipe reproduces baseline bytes."""
    root, _, _ = built
    out = str(tmp_path / "swiotlb_copy.bpf.o")
    sha = producer.build_base_object(root, out)
    assert sha == producer.BASELINE_COPY_SHA256
    with open(out, "rb") as handle:
        rebuilt = handle.read()
    with open(proof.base_object(root), "rb") as handle:
        fixture = handle.read()
    assert rebuilt == fixture


def test_loader_sha_path_stable(built, tmp_path):
    """Loader bytes identical from a second staging path.

    DWARF embeds absolute-path-derived crate disambiguators,
    so full bytes vary with the staging path while every
    loader-read section stays identical: the manifest's
    loader sha is the rebuild-stable binding.
    """
    root, _, _ = built
    producer.stage_tree(root, "widened_layout",
                        dest_name="widened_layout-altpath")
    try:
        out = str(tmp_path / "swiotlb_copy-altpath.bpf.o")
        producer.build_staged(root, "widened_layout-altpath",
                              out)
        canonical = os.path.join(
            root, "build", "bpf-negative",
            "swiotlb_copy-widened_layout.bpf.o")
        assert producer.loader_sha256_of(out) == \
            producer.loader_sha256_of(canonical)
    finally:
        shutil.rmtree(os.path.join(
            root, "build", "bpf-negative", "src",
            "widened_layout-altpath"), ignore_errors=True)


def test_frozen_targets_resolve(built):
    """Control leg re-runnable (skips without host BTF)."""
    root, _, _ = built
    detail = proof.check_frozen_targets_resolve(root)
    if detail.startswith("SKIP:"):
        pytest.skip(detail)
    assert "resolve" in detail


@pytest.mark.parametrize("name", producer.NAMES)
def test_proofs_rerunnable(built, name):
    """Every offline proof leg re-runs green per object."""
    root, _, _ = built
    lines = proof.prove_object(root, name)
    assert len(lines) == len(proof.PER_OBJECT_CHECKS) + 1
