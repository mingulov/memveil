<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Releasing

Build once from clean source C, qualify its exact bytes, then promote those
stored bytes. A tag alone never builds or publishes. Qualification and remote
custody are separate from source review. Ordinary Linux does not qualify SNP,
TDX or Hyper-V behavior.

Before freezing C, review `packaging/candidate-policy.json`, including its
required versioned gates, thresholds, claim and trusted Ed25519 public-key
hashes. Empty trust refuses qualification. Commit the intended product version
and policy before building. Runtime, dependency, source, profile or toolchain
changes create a new candidate; they cannot reuse earlier receipts.

Retain the canonical bundle and its copied deb/rpm, a source archive of C,
SBOM and local build provenance together in one directory. Use
`tools/candidate provenance --help` to record the existing local build's
source, toolchain and subjects. `tools/candidate seal --help` verifies the
complete package/file closure and source archive, then writes the immutable
`memveil-candidate/1` manifest once. Its literal SHA-256 is the candidate ID.
No sealing command builds or qualifies software.

Run qualification with `MV_CANDIDATE_MANIFEST` and `MV_BUNDLE_TARBALL`.
The verified loader supplies the packaged executable, BPF and profiles; an
explicit competing executable/package/library override is refused. Retain
independent oracle inputs, signed receipt bindings, environment identities
and cleanup results. `tools/kernel-matrix --verify-out --out DIR
--export-tested PATH` re-executes retained predicates for every locked row.
Historical row booleans alone cannot produce a tested export.

Create an evidence-only descendant Q with the manifest, qualification record
and tested payload under the finite paths described in
[qualification records](packaging/qualifications/README.md).
`tools/candidate qualify --help` verifies every required signed receipt and
re-derives its oracle comparison before exporting the complete tested payload.
The matrix gate also re-runs every locked row's predicates. Required skips,
missing inputs or invalid signatures refuse. Initial Q has no remote IDs.
The source-pinned limits preserve 600,000 replay events, 256 MiB RSS,
65,536 regions in 60 seconds, summary overhead limits, at least 30 minutes
mixed live work and more than 70 minutes pool sampling. Real-platform gates
remain required for their corresponding claims.

Remote import requires a separately authorized draft holding release in the
same repository, with a `candidate-` ref and exact asset IDs. The draft holds
the six candidate artifacts and `qualification-evidence.tar.gz`, whose digest
and size Q records. That archive contains retained gate inputs, signatures,
public keys and an exactly matching signed `SHA256SUMS.txt`. Import verifies
Q's evidence-only ancestry, source, package closure, source archive, SBOM,
truthful local provenance, signed checksums and all required receipts. It
creates no release and publishes nothing. The explicit dispatch mode `import`
requires `ARM-IMPORT` and a reviewed JSON request with `repository`,
`source_commit`, `qualification_commit`, `candidate_sha256`, `release_id`
and the exact basename-to-ID `asset_ids` map.

The import workflow signs a custom `memveil-candidate-import/1` custody
statement, explicitly identifying `local-build` origin. It retains immutable
files for 90 days and reports run/artifact IDs and artifact digest. Record
these in `remote.json` in an evidence-only successor of Q. A hosted build is a
different candidate and cannot use this import statement as build provenance.

Dispatch `dry-run` with `ARM-DRY-RUN`, the final candidate source, Q, immutable
`run_id`/`artifact_id` and existing final `tag`. It verifies stored files and
trusted GitHub custody without creating a release. Complete the tampered
payload, independent attestation, required-check enforcement and no-overwrite
remote checks; retain their signed oracle inputs and immutable check/run IDs.
Only `promote` with `ARM-PROMOTE` accepts the complete remote receipt and
publishes verified stored bytes. The tag must name C and match the actual
bundle and source product version. Version 0.1 requires the ordinary-preview
claim, 0.2 the SNP-journal claim, and 0.3 the security-workflow claim. Existing
or conflicting releases fail;
interrupted drafts require separate cleanup authorization. `v0.*` and
hyphenated versions remain prereleases. Nothing here authorizes a dispatch,
ref creation, upload, publication or protection change by itself.

Dispatch from C or an evidence-only descendant; a different workflow source
is refused. The workflow's `release-custody` environment and required checks need actual
repository enforcement and an independent consumer test before release.
GitHub [release asset IDs](https://docs.github.com/en/rest/releases/assets),
[artifact IDs and expiry](https://docs.github.com/en/rest/actions/artifacts),
and [attestation identity filters](https://cli.github.com/manual/gh_attestation_verify)
are checked by `tools/candidate-custody`. Local fake-API tests do not prove
remote enforcement. `tools/test candidate-custody` runs those local contracts.
