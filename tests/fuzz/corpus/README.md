<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Fuzz corpus provenance

No bulk corpus is committed. `run.py` retains the four original seed families
(attempts, nested lifecycle, detail/counter loss, and counter deltas), adds the
sealed complete/partial/empty captures, and derives a checkpoint from the sealed
complete capture. Seed N selects one of these eight families deterministically.
The checkpoint helper updates open-window metadata and preserves literal event
bytes; no frozen fixture is edited.

Twelve deterministic mutation operators exercise byte flips, truncation, line
drop/swap, duplicate keys, integer spelling/range, UTF-8, NUL, missing members,
and deep nesting. One case in five mutates metadata. Normal and strict modes
are sampled; checkpoint cases explicitly request recovery. Every accepted
report is checked against the shipped JSON schema, literal integrity metadata,
quality/exit invariants, and the independent validator's arithmetic. That
validator independently recomputes attempts; other metric families retain its
structural/source checks and their dedicated product test oracles.

Each run first requires valid finalized and checkpoint reports. The required
smoke/campaign gates also run mutations of real reports proving the oracle
rejects empty JSON, false arithmetic, integrity, schema, identity, provenance,
and completeness claims. Refusing every input cannot pass the positive controls.

Receipts under `build/fuzz-*.json` bind the executable, seed file hashes, seed
range, timeout, elapsed time, outcomes, and family sampling. Failed inputs and
the oracle reason remain under `build/fuzz-regressions/`. CI retains those
receipts on every outcome. These are sampling records, not parser branch
coverage. The pinned Mojo build interface has no documented coverage option;
its coverage status is explicitly NOT_MEASURED. No percentage is invented.
