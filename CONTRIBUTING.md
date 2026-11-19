<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Contributing

## Prerequisites

Pinned Rust 1.100.0 toolchain (plus
nightly-2026-05-20 for the eBPF child build)
plus the floored system tools; see
[build](docs/build.md), `rust-toolchain.toml`,
and `Cargo.lock`. No bridge library, no
vendored native dependencies.

## Build and test

```sh
cargo build --release --locked   # build everything
cargo test --workspace --locked  # Rust suites
./tools/test --help              # list harness suites
./tools/test reports             # one harness suite
```

Run the suites that cover a change; run the
full gate before declaring green. Do not
invent test commands: `cargo test` plus
`tools/test` are the runners. Privileged
fixtures belong in the designated isolated
environment.

## Style and scope

- Keep changes scoped to this repository;
  coordinate a pinned-input change with the
  gates that pin it and matching tests.
- Every first-party source file carries an
  SPDX header; keep the [agent
  instructions](AGENTS.md) measurement
  invariants (attempt vs copy vs success,
  unknown is not zero, no inferred
  identity).
- Documentation edits need link, accuracy,
  scope, and whitespace checks, not new
  runtime tests. Behavior changes need
  behavior-focused tests for the affected
  contracts.
- All writing must stand alone: no
  references to private plans, sibling
  checkouts, or internal workflow.

## Licence acceptance

Contributions are accepted under the
repository licence (GPL-3.0-or-later;
eBPF programs GPL-2.0-only; see
[README](README.md#licensing)). Only
contribute material you have the right to
license this way, and preserve source
attribution.
