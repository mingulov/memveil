<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Durability-operator recorded fixtures

Hand-built recorded evidence for the offline operator dry-run
(`capture_durability_operator.py --fixture ... --out ...`). Each
directory holds one checkpoint-leg record: the arranged plan, the
oracle log with window markers, the promised barrier, the recovered
filesystem identity, and the raw capture bytes the prefix verdict
re-verifies. Bytes are fixed (not sampled) so the dry-run is
deterministic.

- `good/`: honest recovery -- same UUID, unchanged prefix. PASS.
- `uuid-drift/`: the recovered UUID differs from the promised one. FAIL.
- `prefix-drift/`: the raw bytes re-verify to a different prefix than
  promised. FAIL.
- `pool-only/`: sampling evidence with no operator records. NOT RUN.
