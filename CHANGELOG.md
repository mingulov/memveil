<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Changelog

Releases are `vX.Y.Z` git tags with GitHub
Releases carrying the bundle, `.deb`, `.rpm`,
SBOM, checksums, and collected payload manifest
(see [releasing](RELEASING.md)). Entries name
user-visible changes only; commit history has
the rest.

## Unreleased

- Pinned toolchain moves to pixi 0.83.0 and
  Mojo 1.2.0; libbpf-mojo 0.2.2.
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
- Release integrity: every package is
  checked against the committed tested
  payload, and releases publish an SBOM
  with signed build provenance as
  prereleases without overwrite.
- Ratified kernel floors (attempt 6.0,
  lifecycle/copy 6.11, ceiling 7.3, BTF
  required) and the evolution and support
  policy.

## v0.1.0 -- 2026-10-24

Development prerelease: attempt, lifecycle,
and copy collection with offline
analysis/reporting, live and replay `top`,
passive `doctor`, local `qualify` receipts,
and standalone build/test/package wrappers.
Only the `.deb` binary ran on the kernel
matrix; details in
[release notes](docs/release-notes.md).
