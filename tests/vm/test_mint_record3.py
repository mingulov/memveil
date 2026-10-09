#!/usr/bin/env python3
"""Host-side tests for the record3 minter transform.

apply_tracing is shared by the record3 lane and the gate
emitter: pre-flip docs gain the frozen tracing set, post-flip
docs verify their base and rebuild tracing from current
builds, and drift warns. Needs the built BPF objects for BTF
parsing; skips honestly without them.
"""
import copy
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mint_record3_profile as m

NEED_BUILDS = pytest.mark.skipif(
    not (os.path.isfile(m.LC_OBJ) and os.path.isfile(m.CP_OBJ)),
    reason="needs built lifecycle/copy objects")


def shipped():
    return json.loads(m.DOC.read_text())


def strip_to_preflip(doc):
    doc = copy.deepcopy(doc)
    doc["hooks"] = [h for h in doc["hooks"]
                    if h["kind"] != "tracing"]
    doc["identity"]["source"]["note"] = " ".join(
        doc["identity"]["source"]["note"].split()[:8])
    for cap in doc["capabilities"]:
        if cap["id"] in ("mapping-lifecycle", "copy-actual"):
            cap["status"] = "unsupported"
            cap["hooks"] = []
            cap["reason"] = "x"
    return doc


@NEED_BUILDS
def test_preflip_gains_frozen_tracing():
    out = m.apply_tracing(strip_to_preflip(shipped()),
                          m.LC_OBJ, m.CP_OBJ, "lr", "cr", "n")
    names = [h["name"] for h in out["hooks"]
             if h["kind"] == "tracing"]
    assert names == [t[0] for t in m.TRACE_HOOKS]
    fields = out["identity"]["source"]["note"].split()
    assert len(fields) == 12
    assert fields[8].startswith("lc_object=sha256:")
    caps = {c["id"]: c for c in out["capabilities"]}
    assert caps["mapping-lifecycle"]["status"] == "supported"
    assert caps["mapping-lifecycle"]["reason"] == "lr"
    assert caps["copy-actual"]["hooks"] == list(m.CP_HOOK_NAMES)


@NEED_BUILDS
def test_postflip_idempotent():
    once = m.apply_tracing(shipped(), m.LC_OBJ, m.CP_OBJ,
                           "lr", "cr", "n")
    twice = m.apply_tracing(copy.deepcopy(once), m.LC_OBJ,
                            m.CP_OBJ, "lr", "cr", "n")
    assert twice == once


@NEED_BUILDS
def test_tracing_matches_fresh_mint():
    fresh = m.apply_tracing(strip_to_preflip(shipped()),
                            m.LC_OBJ, m.CP_OBJ, "lr", "cr",
                            "n")
    kept = m.apply_tracing(shipped(), m.LC_OBJ, m.CP_OBJ,
                           "lr", "cr", "n")
    assert kept["identity"] == fresh["identity"]
    assert kept["capabilities"] == fresh["capabilities"]

    def tracing(doc):
        return [(h["name"], h["kind"], h["function"],
                 h["attach"], h["signature"])
                for h in doc["hooks"]
                if h["kind"] == "tracing"]

    assert tracing(kept) == tracing(fresh)


@NEED_BUILDS
@pytest.mark.parametrize("note", [
    # Shape only: values are the live gate's job, so a
    # well-formed note with wrong values still mints.
    "a b c d e f g",
    "config=x config_src=y btf=z format=w object=v image=u "
    "image_bid=t",
    "config=x config_src=y btf=z format=w object=v image=u "
    "image_bid=t ring_bytes=1 lc_object=q lc_ring_bytes=1 "
    "cp_object=e",
    "config=x config_src=y btf=z format=w object=v image=u "
    "image_bid=t ring_bytes=1 WRONG=1 lc_ring_bytes=1 "
    "cp_object=1 cp_ring_bytes=1",
    " ".join("f%d" % i for i in range(13)),
])
def test_malformed_notes_refused(note):
    doc = shipped()
    doc["identity"]["source"]["note"] = note
    with pytest.raises(SystemExit):
        m.apply_tracing(doc, m.LC_OBJ, m.CP_OBJ,
                        "lr", "cr", "n")


@NEED_BUILDS
def test_drift_warns_and_rebuilds(capsys):
    doc = shipped()
    fields = doc["identity"]["source"]["note"].split()
    assert len(fields) == 12
    fields[9] = "lc_ring_bytes=4096"
    doc["identity"]["source"]["note"] = " ".join(fields)
    out = m.apply_tracing(doc, m.LC_OBJ, m.CP_OBJ,
                          "lr", "cr", "n")
    assert "differ from current builds" in capsys.readouterr().err
    rebuilt = out["identity"]["source"]["note"].split()
    assert rebuilt[9] != "lc_ring_bytes=4096"
    assert rebuilt[9].startswith("lc_ring_bytes=")


@NEED_BUILDS
def test_steady_state_silent(capsys):
    m.apply_tracing(shipped(), m.LC_OBJ, m.CP_OBJ,
                    "lr", "cr", "n")
    assert capsys.readouterr().err == ""


@NEED_BUILDS
@pytest.mark.parametrize("field,value", [
    ("signature", "u64 f(void)"),
    ("function", "other_fn"),
    ("attach", "fentry"),
    ("kind", "tracepoint"),
])
def test_kept_hook_drift_refused(field, value):
    doc = shipped()
    for h in doc["hooks"]:
        if h["name"] == m.TRACE_HOOKS[0][0]:
            h[field] = value
    with pytest.raises(SystemExit):
        m.apply_tracing(doc, m.LC_OBJ, m.CP_OBJ,
                        "lr", "cr", "n")
