#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Live top walkthrough: workload, replay equality, witness, no leak.

Boots the guest, runs the real `memveil top --output` with the
attempt plus lifecycle plus copy channels under the shipped
narrow profile while ordinary direct-I/O disk traffic flows
through the swiotlb path, then checks host-side: the final
live block equals a replay of the retained capture, pool
sampling stayed bounded, the independent debugfs witness
corroborates the captured pool values, BPF inventory settled
back to baseline, and honest unknowns stay explicit.
"""

import json
import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from lifecycle_env import (BRIDGE, COPY_PROBE, LIFECYCLE_PROBE,
                           ensure_oracle_module,
                           require_lifecycle_env)
from test_attempt_capture import cleanup
from vm_boot import run_guest, verify_exports

REPO = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MEMVEIL = os.path.join(REPO, "build", "memveil")
ATTEMPT_PROBE = os.path.join(
    REPO, "build", "bpf", "swiotlb_attempt.bpf.o")
NARROW_PROFILE = "linux-x86_64-7.0.0-34-generic"
POOL_SLOT_BYTES = 2048


def _events(path):
    with open(path) as handle:
        return [json.loads(line) for line in handle
                if line.strip()]


def _blocks(text):
    """Split live/replay stdout into (seq, horizon, body) blocks."""
    blocks = []
    seq = None
    horizon = None
    body = []
    for line in text.splitlines(keepends=True):
        if line.startswith("--- refresh "):
            if seq is not None:
                blocks.append((seq, horizon, "".join(body)))
            head = line[len("--- refresh "):]
            seq = int(head.split(" @ ")[0])
            horizon = int(head.split(" @ ")[1].split(" ns ")[0])
            body = []
        elif seq is not None:
            body.append(line)
    if seq is not None:
        blocks.append((seq, horizon, "".join(body)))
    return blocks


def test_topwalk_live_top_walkthrough():
    require_lifecycle_env(LIFECYCLE_PROBE, COPY_PROBE,
                          ATTEMPT_PROBE, BRIDGE)
    ensure_oracle_module()
    tmp, proc = run_guest("topwalk", timeout=900)
    try:
        assert proc.returncode == 0, \
            "guest failed: %s" % proc.stderr[-2000:]
        got = verify_exports(
            tmp, "topwalk",
            ["identity.json", "walk.json", "live.txt",
             "live.err", "cap-session.json",
             "cap-events.ndjson"])
        ident = json.loads(got["identity.json"].read_text())
        assert ident["release"] == "7.0.0-34-generic", ident
        ledger = json.loads(got["walk.json"].read_text())
        assert ledger["memveil_rc"] == 4, ledger
        assert ledger["end_reason"] == "duration", ledger
        for cap in ("bounce_attempts", "mapping_lifecycle",
                    "copy_bytes"):
            assert ledger["profile_ids"][cap] == \
                NARROW_PROFILE, ledger
        assert ledger["bpf_after"] == ledger["bpf_before"], \
            ledger
        session = json.loads(
            got["cap-session.json"].read_text())
        assert session["capture"]["finalized"] is True, session
        events = _events(got["cap-events.ndjson"])
        assert events, "retained capture is empty"
        # Reassemble the retained capture and replay it.
        capdir = os.path.join(tmp, "cap")
        os.makedirs(capdir, exist_ok=True)
        shutil.copyfile(got["cap-session.json"],
                        os.path.join(capdir, "session.json"))
        shutil.copyfile(got["cap-events.ndjson"],
                        os.path.join(capdir, "events.ndjson"))
        replay = subprocess.run(
            [MEMVEIL, "top", capdir],
            capture_output=True, text=True, timeout=300)
        assert replay.returncode == ledger["memveil_rc"], \
            replay.stderr[-2000:]
        live_text = got["live.txt"].read_text()
        live_blocks = _blocks(live_text)
        replay_blocks = _blocks(replay.stdout)
        assert live_blocks, "live printed no refresh blocks"
        assert replay_blocks, "replay printed no blocks"
        # Horizons rise; the final live block equals the
        # replay final over the same retained bytes (bodies
        # byte-equal, same window-end horizon; only the
        # refresh numbering differs by construction).
        horizons = [horizon for _, horizon, _ in live_blocks]
        assert horizons == sorted(horizons), horizons
        assert live_blocks[-1][1] == \
            replay_blocks[-1][1], (live_blocks[-1][1],
                                   replay_blocks[-1][1])
        assert live_blocks[-1][2] == \
            replay_blocks[-1][2], "live final != replay final"
        # Bounded sampling: the 15 s window fires about once
        # a second past the closing baseline/final pair.
        pools = [e for e in events
                 if e["kind"] == "pool_sample"]
        periodic = len(pools) - 2
        assert 5 <= periodic <= 25, len(pools)
        # Independent witness: slab count stable, captured
        # capacity exactly the witness slabs, every used
        # value inside the physical range.
        witness = ledger["witness"]
        assert witness["nslabs"] == \
            witness["nslabs_after"], witness
        capacity = witness["nslabs"] * POOL_SLOT_BYTES
        assert capacity > 0, witness
        for sample in pools:
            data = sample["data"]
            assert data["capacity_bytes"] == str(capacity), \
                data
            used = data["used_bytes"]
            assert used is None or \
                0 <= int(used) <= capacity, data
        # The workload really wrote: block-layer write
        # completions rose under the capture.
        workload = ledger["workload"]
        writes_before = int(workload["stat_before"][4])
        writes_after = int(workload["stat_after"][4])
        assert writes_after > writes_before, workload
        # Quiet run, quiet stderr: nothing but blocks on
        # stdout and no diagnostics at all.
        assert got["live.err"].read_text() == "", \
            got["live.err"].read_text()[-500:]
        # Honest unknowns stay explicit in the final answer,
        # and the binding names the narrow profile.
        final_body = live_blocks[-1][2]
        assert "loss=unknown" in final_body, final_body[-2000:]
        assert "validated %s: bindings hold" % \
            NARROW_PROFILE in final_body, final_body[-2000:]
        print("topwalk: %d live blocks, %d periodic samples, "
              "replay-equal final" % (len(live_blocks),
                                      periodic))
    finally:
        cleanup(tmp)
