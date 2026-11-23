<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Changelog

Releases are `vX.Y.Z` git tags with GitHub
Releases carrying the bundle, `.deb`, `.rpm`,
SBOM, checksums, and collected payload manifest
(see [releasing](RELEASING.md)). Entries name
user-visible changes only; commit history has
the rest.

## v0.2.0 -- 2026-11-23

RnD prerelease on sealed bytes (seal
`08bdeaed2e8646c28b1a6dda760ae9071f603816ab8e219600cb465749b890c9`,
source `bdf641c36addc345f3fb6d8bf925059c6f1fa714`;
per-row evidence in [support](docs/support.md)):

- `record`, `report`, and `top` exit 0 for
  valid captures and carry a `verdict` field;
  `--strict` restores a nonzero exit on
  materially incomplete evidence.
- Clearer reporting under load: pre-window
  release explanations, long-lived mapping
  non-evaluation notes, per-channel loss
  suffixes, and a larger writer identity
  budget.
- New `bind-profile` verb mints bound
  profile documents from live evidence.
- Pool sampling persists past the routine
  sample cap under pressure, with the
  thinning named in the session note.
- Release integrity: releases publish a real
  SBOM (`memveil.spdx.json`) plus unsigned
  build provenance (`memveil.provenance.json`,
  described as such) as prereleases without
  overwrite. The full tested-payload export
  follows the post-tag full-matrix repeat.
- Ratified kernel floors (attempt 6.0,
  lifecycle/copy 6.11, ceiling 7.3, BTF
  required) and the evolution and support
  policy.
- Rust userspace: collection, CLI, and
  reporting now build from the Cargo
  workspace, with the BPF loader statically
  linked and the inspection objects embedded
  in the binary.

## v0.1.0 -- 2026-10-24

Development prerelease: attempt, lifecycle,
and copy collection with offline
analysis/reporting, live and replay `top`,
passive `doctor`, local `qualify` receipts,
and standalone build/test/package wrappers.
Only the `.deb` binary ran on the kernel
matrix; details in
[release notes](docs/release-notes.md).
