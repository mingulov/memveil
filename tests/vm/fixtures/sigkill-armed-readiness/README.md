<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# SIGKILL armed-readiness export fixture

Byte-identical guest export from an armed readiness run (empty durable
prefix): `barrier.json`, `result.json`, `checkpoint.json`,
`prefix-events.ndjson` (empty), `record.stderr` (empty).

`test_collector_sigkill.py` replays this export through `host_verify`
offline — no VM needed — so the host judge is pinned to the exact
7-key integrity shape the product seals (`algorithm`, `events_bytes`,
`events_sha256`, `first_seq`, `kinds`, `last_seq`, `line_count`;
sequence bounds null on the empty prefix). Do not edit: the barrier
checkpoint digest binds `checkpoint.json`, and the per-key tamper tests
derive their wrong values from these bytes.
