<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Releasing

Releases are cut by dispatch, never by tag push. The `release`
workflow (`.github/workflows/release.yml`) runs one stage per
dispatch; each dispatch runs only its own stage's jobs and
never rebuilds another stage's bytes. Custody stages consume
stored bytes with digest verification (sealed artifact, draft
assets, remote artifact). This file states the order so
a human can follow and audit it.

Mode to jobs:

- `seal` runs `seal`, `sign`, and `qualify` (`qualify` only
  after the holding draft exists; re-dispatch `seal` then).
- `import` runs `import` only: it stages the holding draft
  byte-for-byte, stores the remote artifact, and attests.
- `dry-run` runs `dry-run` only: it consumes the recorded
  import and validates the proposed tag without mutation.
- `promote` runs `promote` only: it consumes the recorded
  import and publishes the stored bytes.

## Prepare the candidate

1. Pick the source commit C and fill in
   `packaging/candidate-policy.json` there: the release claim,
   the required gates, the trusted qualifier key digests, and
   the campaign retention (30 to 90 days).
2. Run the kernel matrix campaign against the tree at C and sign
   the gate receipts. Pack the campaign evidence as
   `qualification-evidence.tar.gz` with `qualification.json`
   beside the matrix directory at the archive root.

## Seal and qualify

3. Dispatch the workflow with `mode: seal`,
   `candidate_sha256`, and `source_commit: C`. The seal job
   builds the bundle, `.deb`, and `.rpm` from C, emits the
   frozen SBOM, records provenance, seals `candidate.json`,
   signs the artifact checksums, and refuses unless the sealed
   digest equals the dispatched one. The qualify job skips
   until the holding draft below exists.
4. Upload the six sealed artifacts plus the evidence archive to
   a draft release tagged `candidate-<candidate_sha256>`
   (seven assets, no more), then dispatch `mode: seal` again:
   the qualify job re-derives every required signed gate over
   the campaign evidence, then exports the tested payload
   through the matrix lock binding and uploads it. Commit
   Q, evidence-only over C, carrying
   `packaging/qualifications/candidate.json`,
   `packaging/qualifications/qualification.json`, and the
   exported `packaging/tested-payload.sha256`; see
   `packaging/qualifications/README.md` for the layout and the
   evidence-only rule.

## Walk the custody stages

5. Dispatch `mode: import` with the workflow ref at Q. The job
   consumes the stored sealed bytes via the draft assets
   (digest-verified, no rebuild) and stores them as the
   `candidate-<candidate_sha256>` workflow artifact. Record the
   reported run, artifact, and custody digests in
   `packaging/qualifications/remote.json` and fold them into Q
   (still evidence-only over C).
6. Dispatch `mode: dry-run` with the ref at Q, as its own
   dispatch. The job consumes the recorded import only and
   validates the proposed `vX.Y.Z` tag without mutating
   anything; it refuses when the tag already exists, so
   dry-run never triggers a fresh import and never chains
   into promote inside one run.
7. After the dry-run dispatch is green, tag `vX.Y.Z` on C
   (owner step, outside the workflow). Then dispatch
   `mode: promote` with the ref at Q and
   `promote_authorization` retyping the candidate digest.
   The job consumes the recorded import only, requires the
   tag to resolve to C, then creates and publishes the
   release with the qualified notes. A rerun of the same tag
   fails instead of replacing uploaded files; rollback is
   a new tag.
