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
counts are extensible. Payload comparison covers every copied canonical bundle
file and its installed mapping, including runtime libraries, BPF, profiles,
semantic data, docs and licenses. Adapter-generated package metadata, man
pages and completions are outside that copied-file comparison; each complete
archive is separately sealed by size and SHA-256. Extra ELF/shared libraries
anywhere in an extracted package are refused. Archive links and special files are refused. Extracted
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

A `memveil-qualification/1` document has exactly `schema`,
`candidate_sha256`, `source_commit`, `claim`, `evidence_archive` and `gates`.
The archive record has `name="qualification-evidence.tar.gz"`, string `size`
and `sha256`; it is an evidence container, never a runtime package. Each
required gate maps to `receipt`, `receipt_sha256`, `signature`, `public_key`
relative paths inside its single extracted root. Sign receipts with
`ssh-keygen -Y sign -n memveil-candidate -f PRIVATE_KEY receipt.json`.
Private keys are never stored in the evidence archive or repository.

Each canonical `memveil-gate-receipt/1` has `schema`, versioned `gate`,
`candidate_sha256`, `source_commit`, `inputs`, `inputs_sha256`.
`memveil-gate-input/1` contains `schema`, `environment`, `product`, `oracle` and `sources`.
The latter two maps contain canonical unsigned decimal measurements with the
exact predicate names pinned in policy. `equal` needs a positive exact match;
`zero` needs both zero; bounds use source-pinned thresholds when present.
`sources` maps each side and measurement name to a retained `file`, its
`sha256`, a `path` array of JSON keys or array indices, and `encoding` (`u64`
or `boolean`). Product and oracle use separate source files. Qualification
re-reads those files and extracts each value before comparing it, including
integer values above 2^53. Missing or mismatched source values refuse.
The trusted signer must independently obtain the oracle measurements and
retain their underlying records. A signed label saying PASS is insufficient.
The paced-replay adapter additionally re-derives the minimum real read/EOF
call count from the independent byte extent; device/inode, EOF, request size,
actual duration and wall time are required alongside events and measured RSS.

`kernel-matrix/2` instead uses `memveil-matrix-input/1` with `schema`,
`matrix_directory` and `lock_sha256`. The directory retains each row's
`oracle-inputs.json` and receipt. Export requires every source-locked row,
matching candidate runtime/profile identities and actual re-execution of the
matrix predicates. Earlier receipts without retained predicate inputs cannot
be upgraded by copying their status strings.

The signed `SHA256SUMS.txt` contains exactly the six artifact hashes in name
order, two spaces between hash and basename, and trailing newlines. Its
signature is `SHA256SUMS.txt.sig`; the public key is `signer.pub`.

A remote successor adds `remote.json` with schema `memveil-remote-custody/1`,
`candidate_sha256`, `source_commit`, `repository`, decimal-string
`repository_id`, `run_id`, `artifact_id`, `artifact_sha256`, `signer_commit`,
`custody_sha256` and `checks`. Initial remote checks may be empty for dry-run;
promotion requires all five checks named in RELEASING. Each binds `check_id`,
`run_id`, `head_sha`, `receipt`, `inputs`, `signature_base64`, `public_key`.
Remote bindings embed `receipt`, `inputs`, `signature_base64` and `public_key`
alongside the check/run/head IDs, so adding remote evidence does not change the
already imported local evidence archive. The signed canonical receipt has
schema `memveil-remote-gate/1`, `gate`, `candidate_sha256`, `source_commit`, and
`inputs_sha256`. Inputs use `memveil-gate-input/1`; they require `failures=0`
and a positive exact count named `refusals`, `verified_files`,
`verified_subjects`, `enforced_checks` or `preserved_assets`, respectively.
The remote check's GitHub identity and result are necessary alongside these
signed, re-derived measurements. Artifact IDs and expiry are checked afresh.
