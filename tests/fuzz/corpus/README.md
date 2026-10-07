<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Fuzz corpus provenance

No bulk corpus is committed. `run.py` mutates four seed
captures deterministically (seed N drives `random.Random(N)`
and picks seed N mod 4):

- `tests/fixtures/attempts` (attempt-only replay)
- `tests/fixtures/lifecycle/lifecycle-nested` (lifecycle replay)
- `tests/fixtures/reader/quality-detail-counters` (detail loss
  plus counter snapshots)
- `tests/fixtures/reader/counters` (counter deltas)

Twelve mutation operators cover byte flips, truncation, line
drop/swap, duplicate keys, integer spelling and range, UTF-8
breaks, NUL injection, dropped members, and deep nesting;
one case in five mutates `session.json` instead of the event
stream. Every operator is listed in `run.py`; no hidden
dictionaries.

## Campaign receipt fields

Each campaign records: binary path and sha256, seed range,
case count, failures, per-case timeout, retained regression
seeds, and wall time. Minimized regressions land under
`tests/fuzz/regressions/seed-<N>/` with an `oracle.txt`
naming the violated property; promoted regressions become
named adversarial fixtures instead of bulk artifacts.

Fuzzing time is sampling, not exhaustive proof: it bounds
untrusted-input risk alongside the exact-boundary fixtures,
never in place of them.
