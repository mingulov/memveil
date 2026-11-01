<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Candidate qualification records

A candidate is a local build whose exact bytes are sealed once by
`tools/candidate seal --help`. Sealing does not qualify the candidate.
`tools/candidate verify-bundle --manifest candidate.json --bundle bundle.tar.gz
--destination NEW_DIRECTORY` verifies and extracts existing bytes without building.
The destination must not exist. Failure never permits a build fallback.

The Python loader interface is `candidate.load_manifest(path,
expected_digest=None)` followed by `candidate.verify_bundle(manifest,
bundle_path, destination)`. The latter returns the extracted bundle root.
Both raise on invalid input. Import from the repository's `tools` directory.
Runtime qualification uses `MV_CANDIDATE_MANIFEST` and `MV_BUNDLE_TARBALL`;
the qualification runner must pass verified paths to each consumer.

`memveil-candidate/1` uses canonical JSON: sorted keys, compact separators,
ASCII escaping, and exactly one trailing newline. Its SHA-256 is the local
candidate ID. The exact fields are:

- `schema`: `memveil-candidate/1`; `origin`: `local-build`.
- `source`: `commit`, `tree` (full Git identities), `inventory_sha256`.
- `toolchain`: `lock_sha256`, `pixi_lock_sha256`.
- `build_receipt_sha256`, `bundle_manifest_sha256`, `policy_sha256`.
- `canonical_runtime`: the complete `memveil-runtime/1` object, including CPU
  contract and sorted unique file entries with type, path, size and SHA-256.
- `files`: every copied bundle file and SHA-256, excluding `MANIFEST.json`.
- `artifacts`: one each of `bundle`, `deb`, `rpm`, `source`, `sbom`, and
  `provenance`, each with `role`, basename `name`, `size`, and `sha256`.

Sizes are canonical unsigned decimal strings. Missing, duplicate, unknown,
zero-placeholder, escaping and inconsistent fields fail closed. Runtime entry
counts are extensible. Archive links and special files are refused. Extracted
engine CPU properties, runtime closure and every copied file are verified.

The source commit C remains immutable. Evidence-only descendants Q may change
only `packaging/tested-payload.sha256`, `candidate.json`, `qualification.json`
and `remote.json` in this directory. These finite paths define
`memveil-evidence-exclusions/1`; other files here remain source inputs.
The build inventory includes release policy and tooling. Full source exports
retain evidence files. An intermediate source change followed by a revert is
not an evidence-only history. Initial qualification has no remote IDs.

Qualification requires a source-pinned policy, signed retained input bindings
and independent oracle comparisons. No trusted release signing key is bundled;
operators must pin their public-key hash in the reviewed policy before C.
Test keys are ephemeral fixtures and grant no product trust. Existing zero
payload placeholders remain unqualified until every required real gate passes.
