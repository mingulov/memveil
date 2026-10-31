<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Releasing

Releases are cut by tag from a clean tree.
The `release` workflow (`.github/workflows/release.yml`)
does the rest; this file states the order so a
human can follow and audit it.

## Qualify first

1. Run the kernel matrix against the `.deb`
   built from the candidate tree, plus the
   `.rpm` install journey and the bundle
   clean-room replay from the same tree.
2. Refill `packaging/tested-payload.sha256`
   with `tools/payload-gate --collect` over
   the three packages the lanes ran, and
   commit the result. The gate fails while
   any entry is the zero placeholder.

## Tag and publish

3. Tag `vX.Y.Z` on the qualified commit and
   push the tag. `v0.*` and hyphenated tags
   publish as prereleases.
4. The workflow provisions the locked
   toolchain, runs the Tier 1 + Tier 2 gate
   suites, builds the bundle, `.deb`, and
   `.rpm`, re-verifies each through its own
   lane, and refuses the set unless every
   payload hash matches the committed
   receipt.
5. It then emits the SBOM (`tools/sbom`),
   writes `SHA256SUMS.txt` over the set,
   attests Sigstore build provenance, and
   uploads the bundle, `.deb`, `.rpm`,
   SBOM, checksums, and collected manifest
   to the tag's GitHub Release with the
   committed release notes. A rerun of the
   same tag fails instead of replacing
   uploaded files; rollback is a new tag.

## Dry run

Dispatch the workflow manually to build
everything without publishing; the set is
kept as a `release-dry-run` workflow
artifact. Dry-run the gate red (placeholder
or altered payload refuses) and green
(recorded payload passes) before tagging.
