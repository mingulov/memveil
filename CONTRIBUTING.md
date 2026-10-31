<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Contributing

## Prerequisites

Pinned Mojo 1.2.0 toolchain via pixi plus the
floored system tools; see [build](docs/build.md)
and `toolchain.lock.json`. The native bridge
resolves from the hash-pinned vendored bundle
in `third_party/`, or an explicit matching
`LMB_PACKAGE`.

## Build and test

```sh
./tools/build                    # build everything
./tools/test --help              # list suites
./tools/test unit                # one suite
```

Run the suites that cover a change; run the
full gate before declaring green. Do not
invent a Mojo test command: `tools/test` is
the only runner. Privileged fixtures belong
in the designated isolated environment.

## Style and scope

- Keep changes scoped to this repository;
  coordinate a library ABI change with an
  explicit dependency revision and matching
  tests.
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
