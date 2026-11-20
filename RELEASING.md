<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Releasing

Releases are cut locally first, then carried by dispatch.
The operator builds, seals, signs, campaigns, qualifies,
and exports on a machine they control, commits the
qualification records, stages the holding draft, and
dispatches the `release` workflow
(`.github/workflows/release.yml`) one stage at a time.
Hosted jobs never build, seal, or sign: they consume draft
or recorded bytes with digest verification only. This file
states the exact choreography so a human can follow and
audit it; `packaging/qualifications/README.md` states the
record layout and the evidence-only rule.

Mode to jobs (dispatch with the ref at the stated commit):

- `qualify` runs `qualify` only, with the ref at Q1: it
  re-verifies the draft assets by recorded ID against Q1's
  records (digests plus qualify plus export, zero builds)
  and refuses unless its export equals Q1's committed
  `packaging/tested-payload.sha256`.
- `import` runs `import` only, with the ref at Q1: it stages
  the holding draft byte-for-byte, stores the remote
  artifact, and attests.
- `dry-run` runs `dry-run` only, with the ref at Q2: it
  consumes the recorded import only and validates the
  proposed `vX.Y.Z` tag without mutating anything; it
  refuses when the tag already exists.
- `promote` runs `promote` only, with the ref at Q3: it
  consumes the recorded import only, requires the tag to
  resolve to C, then creates and publishes the release with
  the qualified notes. A rerun of the same tag fails instead
  of replacing uploaded files; rollback is a new tag.

Q1 is the qualification commit over C carrying
`packaging/qualifications/candidate.json`,
`packaging/qualifications/qualification.json`, and
`packaging/tested-payload.sha256`. Q2 is Q1 plus
`packaging/qualifications/remote.json` with the four
pre-dry-run check bindings, committed after a clean
import. Q3 is Q2 with `remote.json` finalized to all five
bindings, committed after a green dry-run. Dispatches name
a branch (or tag) whose HEAD is the required commit: `gh
workflow run --ref` takes a branch or tag, never a raw SHA,
and the run checks out the ref at start time, so freeze one
branch per Q (`release-q1`, `release-q2`, `release-q3`)
and never move a Q branch after dispatching on it.

## Prerequisites

- A clean checkout at the source commit C. Everything
  below that reads the source runs with `--root .` /
  `--source-root .` / `--source-tree .` from that checkout.
- `packaging/candidate-policy.json` committed at C: the
  release claim, the required gates, the trusted qualifier
  key digests, and the campaign retention (30 to 90 days).
  Claims pair with versions: `ordinary-preview` for `0.1.x`,
  `snp-journal` for `0.2.x`, `security-workflow` for
  `0.3.x`. The shipped template names the required gates,
  `kernel-matrix/2` and `live-campaign/1`, with empty
  `trusted_keys`; fill in the key digest from step 0
  before fixing C.
- The qualifier Ed25519 key (step 0). The same key signs
  the artifact checksums, the gate receipts, and the
  remote-check receipts; its derived public bytes go in
  the policy. THE key location is
  `$HOME/.memveil-qualifier/`, outside the checkout, so
  key material never dirties the tree the seal gates on.
- Toolchains: Rust 1.100.0 (`rust-toolchain.toml`),
  nightly-2026-05-20 plus bpf-linker 0.10.4 for the eBPF
  child build (`build.rs`), packaging tools (`binutils`,
  `cpio`, `dpkg-dev`, `patchelf`, `rpm`), `ssh-keygen`,
  and `gh`.
- Keep every scratch path under the ignored `dist/` tree:
  the seal refuses a dirty source tree, and campaign
  receipts record the worktree state, so outputs anywhere
  else would poison the evidence.

## 0. Key and policy, before C is fixed

Generate the qualifier key OUTSIDE the checkout,
derive the exact public bytes the signer will write, and
hash them for the policy. THE key location is
`$HOME/.memveil-qualifier/`; no key file is ever created
inside the checkout, so this step leaves the tree clean
for the seal's clean-tree gate:

```sh
KEYDIR="$HOME/.memveil-qualifier"
mkdir -p "$KEYDIR"
chmod 700 "$KEYDIR"
ssh-keygen -q -t ed25519 -N '' -f "$KEYDIR/qualifier.key"
ssh-keygen -y -f "$KEYDIR/qualifier.key" \
  > "$KEYDIR/qualifier-derived.pub"
sha256sum "$KEYDIR/qualifier-derived.pub"
```

Keep `KEYDIR` exported for the steps below (like
`CANDIDATE_SHA256` and `DEB`). Put that digest in
`packaging/candidate-policy.json` at C (`trusted_keys`),
with the claim, gates, and retention the release needs,
then fix C with the policy committed.

## Seal and sign locally

Run from the checkout at C (`C` below is the 40-hex
commit). Pin the sealed clock to C first:

```sh
export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct "$C")
```

1. Build the sealable bundle, deb, and rpm from C:

```sh
python3 scripts/package-tarball.py --build --candidate \
  --root . --out dist --tag bundle
python3 scripts/package-deb.py --bundle dist/bundle \
  --out dist/deb
python3 scripts/package-rpm.py --work dist/work/rpm \
  --out dist/rpm --bundle dist/bundle
mkdir -p dist/artifacts
cp dist/bundle.tar.gz dist/artifacts/
set -- dist/deb/*.deb; test $# -eq 1 && cp "$1" dist/artifacts/
set -- dist/rpm/*.rpm; test $# -eq 1 && cp "$1" dist/artifacts/
git archive --format=tar HEAD | gzip -n \
  > dist/artifacts/memveil-source.tar.gz
ls dist/artifacts
```

2. Emit the frozen SBOM (the stamp defaults to
`SOURCE_DATE_EPOCH`):

```sh
cargo build -p memveil-release-entry --locked --offline
DEB=$(echo dist/artifacts/*.deb)
RPM=$(echo dist/artifacts/*.rpm)
target/debug/memveil-release-entry sbom-emit \
  --manifest dist/bundle/MANIFEST.json \
  --out dist/artifacts/memveil.spdx.json \
  --bundle dist/artifacts/bundle.tar.gz \
  --deb "$DEB" \
  --rpm "$RPM" \
  --lock Cargo.lock \
  --ebpf-lock crates/ebpf/Cargo.lock
```

3. Record provenance and seal. The seal prints the
candidate ID; keep it in the environment from here on:

```sh
./tools/candidate provenance \
  --bundle-dir dist/bundle \
  --bundle dist/artifacts/bundle.tar.gz \
  --deb "$DEB" \
  --rpm "$RPM" \
  --source dist/artifacts/memveil-source.tar.gz \
  --sbom dist/artifacts/memveil.spdx.json \
  --out dist/artifacts/memveil.provenance.json \
  --source-root .
CANDIDATE_SHA256=$(./tools/candidate seal \
  --bundle-dir dist/bundle \
  --artifacts-dir dist/artifacts \
  --policy packaging/candidate-policy.json \
  --out dist/candidate.json \
  --source-root .)
```

4. Sign the artifact checksums over exactly the six
sealed artifacts, and prove the evidence key is the
policy key:

```sh
./tools/candidate sign-checksums \
  --artifacts-dir dist/artifacts \
  --key "$KEYDIR/qualifier.key" \
  --out-dir dist/signed
cmp "$KEYDIR/qualifier-derived.pub" dist/signed/signer.pub
ls dist/signed
```

## Campaign, qualify, and export locally

5. Run the kernel matrix campaign against the sealed
bytes. The manifest must sit beside the six artifacts so
the campaign resolves them, and the environment must
carry no `MV_DEB`/`MV_RPM`/`MEMVEIL_TEST_*` overrides
(the candidate input refuses them):

```sh
cp dist/candidate.json dist/artifacts/candidate.json
MV_BUNDLE_TARBALL=$PWD/dist/artifacts/bundle.tar.gz \
MV_CANDIDATE_MANIFEST=$PWD/dist/artifacts/candidate.json \
  ./tools/kernel-matrix --all --out dist/evidence/matrix \
    --deb "$PWD/$DEB"
```

(`--bundle` with the owner bundle dir replaces `--deb`
on guests whose rootfs cannot install the deb; see the
tool header. `--lock` defaults to the checkout's
`tests/vm/kernels.lock.json`, which is C's lock when run
here.)

5b. Run the installed-candidate live campaigns. Each
needs its arming flag plus the same sealed inputs; host
acceptance re-verifies the export from retained bytes
and writes the verified totals into the receipt's
`exit.json`:

```sh
MV_BUNDLE_TARBALL=$PWD/dist/artifacts/bundle.tar.gz \
MV_CANDIDATE_MANIFEST=$PWD/dist/artifacts/candidate.json \
MEMVEIL_VM_PERF=1 tools/test perf-overhead
MV_BUNDLE_TARBALL=$PWD/dist/artifacts/bundle.tar.gz \
MV_CANDIDATE_MANIFEST=$PWD/dist/artifacts/candidate.json \
MEMVEIL_VM_LIVE_SOAK=1 tools/test vm-live-soak
```

Each run prints its receipt directory
(`candidate campaign receipt: ...`); retain the receipt's
`export/` content plus its `exit.json` under
`dist/evidence/live-<mode>/` (`campaign.json`, the
completed legs, the progress files, `exit.json`). Live
campaigns run long (tens of minutes to hours); the pool
leg alone spans over seventy minutes.

6. Stage the signed checksums into the evidence dir,
write the signed matrix gate receipt over the campaign
inventory, and pack the evidence (the packer prints the
archive digest and drops the local-only `vng-cmd.txt`
host command lines, which never ship):

```sh
cp dist/signed/SHA256SUMS.txt dist/signed/SHA256SUMS.txt.sig \
  dist/signed/signer.pub dist/evidence/
python3 - dist/evidence dist/candidate.json <<'EOF'
import hashlib
import sys
sys.path.insert(0, "tools")
import candidate as c
from pathlib import Path
evidence = Path(sys.argv[1])
manifest = c.load_manifest(sys.argv[2])
candidate_id = c.digest_bytes(c.canonical(manifest))
inventory = c.build_evidence_inventory(evidence, "matrix")
inputs = {"schema": "memveil-matrix-input/2",
          "matrix_directory": "matrix",
          "evidence_inventory_sha256":
          c.digest_canonical(inventory)}
(evidence / "matrix-inputs.json").write_bytes(
    c.canonical(inputs))
receipt = {"schema": "memveil-gate-receipt/1",
           "gate": "kernel-matrix/2",
           "candidate_sha256": candidate_id,
           "source_commit": manifest["source"]["commit"],
           "inputs": "matrix-inputs.json",
           "inputs_sha256": hashlib.sha256(
               (evidence / "matrix-inputs.json")
               .read_bytes()).hexdigest()}
(evidence / "matrix-receipt.json").write_bytes(
    c.canonical(receipt))
print("matrix gate inputs ready")
EOF
ssh-keygen -Y sign -f "$KEYDIR/qualifier.key" \
  -n memveil-candidate dist/evidence/matrix-receipt.json
./tools/candidate pack-evidence --evidence-dir dist/evidence \
  --out dist/qualification-evidence.tar.gz
```

Write one receipt per required gate the same way (inputs
file, canonical receipt binding its digest, `ssh-keygen
-Y sign` with namespace `memveil-candidate`).

For `live-campaign/1`, the inputs file carries BOTH campaigns:
the overhead export and the soak export, each twice
(the guest claim from `campaign.json` as the product side
and the host-verified totals from `exit.json` as the
oracle side). The gate requires both campaigns; pool-only
evidence is forbidden and refuses: a `live/` directory
holding only a pool campaign (or any single campaign) never
satisfies this gate. Host acceptance re-verified each
export from retained bytes before writing its `exit.json`,
so transcribing the files is a checkable copy: `qualify`
re-runs the campaign verifier over both retained exports
behind the bindings, not just the signed scalars. Retain
the evidence as `live/overhead/` and `live/soak/` (each a
complete export: `campaign.json`, the `completed-N` legs,
the `progress-N.json` files) with the host oracles beside
them as `live/overhead-exit.json` and `live/soak-exit.json`.
Author `dist/evidence/live-inputs.json` manually with this
exact shape (values from the verified `campaign.json`
totals and the `exit.json` totals per campaign; digests of
the four retained files):

```json
{"schema": "memveil-gate-input/1",
 "environment": "ordinary-linux",
 "product": {"overhead_cleanup_mismatches": "0",
             "overhead_failed_legs": "0", "overhead_legs": "20",
             "overhead_target_failures": "0",
             "soak_cleanup_mismatches": "0",
             "soak_failed_legs": "0", "soak_legs": "31",
             "soak_target_failures": "0"},
 "oracle": {"overhead_cleanup_mismatches": "0",
            "overhead_failed_legs": "0", "overhead_legs": "20",
            "overhead_target_failures": "0",
            "soak_cleanup_mismatches": "0",
            "soak_failed_legs": "0", "soak_legs": "31",
            "soak_target_failures": "0"},
 "sources": {
   "product": {
     "overhead_legs": {"file": "live/overhead/campaign.json",
       "sha256": "<overhead campaign.json sha256>",
       "path": ["totals", "legs"], "encoding": "u64"},
     "soak_legs": {"file": "live/soak/campaign.json",
       "sha256": "<soak campaign.json sha256>",
       "path": ["totals", "legs"], "encoding": "u64"}},
   "oracle": {
     "overhead_legs": {"file": "live/overhead-exit.json",
       "sha256": "<overhead exit.json sha256>",
       "path": ["totals", "legs"], "encoding": "u64"},
     "soak_legs": {"file": "live/soak-exit.json",
       "sha256": "<soak exit.json sha256>",
       "path": ["totals", "legs"], "encoding": "u64"}}}}
```

(Only the `legs` bindings are shown; bind every other
measurement the same way, each to its own campaign file.
The `overhead_legs` value is the verified overhead leg
count: 40, 30, or 20 depending on journal admission. The
`soak_legs` value is the verified soak leg count: at
least 3 (mixed legs plus the closing pool leg). A
pool-only `live/` directory is forbidden: it refuses.)

Then sign the receipt with the authoring CLI and add the
gate entry to `qualification.json` beside the matrix one:

```sh
./tools/candidate write-gate-receipt \
  --gate live-campaign/1 \
  --candidate dist/candidate.json \
  --inputs dist/evidence/live-inputs.json \
  --key "$KEYDIR/qualifier.key" \
  --out dist/evidence/live-receipt.json
```

Step 7's `gates` map gains a `live-campaign/1` entry
pointing at `live-receipt.json`, its digest, the
`live-receipt.json.sig` signature, and `signer.pub`;
step 8's `qualify` rederives it through the
live gate path (signature chain, retained measurement
sources, predicates, plus the campaign verifier run over
both retained exports).

7. Write `qualification.json` beside the archive file,
never inside it: the record carries the archive digest,
so an inner copy would be self-referential and is
refused. Bind one gate entry per receipt:

```sh
python3 - dist dist/candidate.json <<'EOF'
import hashlib
import sys
sys.path.insert(0, "tools")
import candidate as c
from pathlib import Path
scratch = Path(sys.argv[1])
manifest = c.load_manifest(sys.argv[2])
candidate_id = c.digest_bytes(c.canonical(manifest))
archive = scratch / "qualification-evidence.tar.gz"
receipt = scratch / "evidence" / "matrix-receipt.json"
doc = {"schema": "memveil-qualification/1",
       "candidate_sha256": candidate_id,
       "source_commit": manifest["source"]["commit"],
       "claim": "ordinary-preview",
       "evidence_archive":
       {"name": "qualification-evidence.tar.gz",
        "size": str(archive.stat().st_size),
        "sha256": hashlib.sha256(
            archive.read_bytes()).hexdigest()},
       "gates":
       {"kernel-matrix/2":
        {"receipt": "matrix-receipt.json",
         "receipt_sha256": hashlib.sha256(
             receipt.read_bytes()).hexdigest(),
         "signature": "matrix-receipt.json.sig",
         "public_key": "signer.pub"}}}
(scratch / "qualification.json").write_bytes(
    c.canonical(doc))
print("qualification written")
EOF
```

(The `claim` must equal the policy's claim.)

8. Qualify the evidence locally, rechecking the archive
bytes against the record first:

```sh
python3 - dist/qualification-evidence.tar.gz \
  dist/qualification.json <<'EOF'
import sys
sys.path.insert(0, "tools")
import candidate
doc = candidate.read_json(sys.argv[2], sealed=True)
candidate.verify_file(sys.argv[1], doc["evidence_archive"])
print("archive matches the qualification record")
EOF
./tools/candidate qualify \
  --manifest dist/candidate.json \
  --qualification dist/qualification.json \
  --policy packaging/candidate-policy.json \
  --evidence-dir dist/evidence \
  --source-tree .
```

A refusal exits non-zero with the reason; an accept
prints `all required signed qualification inputs
re-derived`.

9. Export the tested payload through the matrix lock
binding (silent on success; `--out` must be the signed
matrix directory):

```sh
MV_CANDIDATE_MANIFEST=$PWD/dist/candidate.json \
./tools/kernel-matrix --verify-out \
  --out dist/evidence/matrix \
  --export-tested dist/tested-payload.sha256 \
  --lock tests/vm/kernels.lock.json \
  --evidence-dir dist/evidence \
  --qualification dist/qualification.json \
  --policy packaging/candidate-policy.json \
  --source-tree .
```

## Commit Q1, stage the draft, walk the dispatches

10. Commit Q1, evidence-only over C, and freeze a
branch on it:

```sh
cp dist/candidate.json packaging/qualifications/candidate.json
cp dist/qualification.json \
  packaging/qualifications/qualification.json
cp dist/tested-payload.sha256 packaging/tested-payload.sha256
git add packaging/qualifications/candidate.json \
  packaging/qualifications/qualification.json \
  packaging/tested-payload.sha256
git commit -m "Qualify $CANDIDATE_SHA256 (evidence-only over $C)"
Q1=$(git rev-parse HEAD)
git diff --name-only "$C..$Q1"
git push origin HEAD:release-q1
```

The diff must list exactly the three qualification
paths. Never move `release-q1` afterwards: the qualify
and import runs pin it.

11. Create the holding draft tagged
`candidate-<candidate_sha256>` and upload all eight
assets (the six sealed artifacts plus the evidence
archive and `qualification.json` beside it), then
record the numeric draft ID:

```sh
TAG=candidate-$CANDIDATE_SHA256
gh release create "$TAG" --draft -t "$TAG" --target "$C" \
  -n "Holding draft for $TAG."
gh release upload "$TAG" \
  dist/artifacts/bundle.tar.gz \
  "$DEB" "$RPM" \
  dist/artifacts/memveil-source.tar.gz \
  dist/artifacts/memveil.spdx.json \
  dist/artifacts/memveil.provenance.json \
  dist/qualification-evidence.tar.gz \
  dist/qualification.json
DRAFT_RELEASE_ID=$(gh api repos/<OWNER>/<REPO>/releases \
  --paginate -q ".[] | select(.tag_name == \"$TAG\") | .id")
test -n "$DRAFT_RELEASE_ID"
```

Listing releases here is fine: the operator holds push
credentials, and the recorded ID is what CI consumes;
no workflow lists releases. Never pass `--clobber`:
re-uploads fail closed instead.

12. Dispatch one hosted stage at a time with the ref at
Q1. Qualify re-verifies independently; import stages
the bytes:

```sh
gh workflow run release.yml --ref release-q1 \
  -f mode=qualify -f candidate_sha256="$CANDIDATE_SHA256" \
  -f source_commit="$C" -f draft_release_id="$DRAFT_RELEASE_ID"
gh workflow run release.yml --ref release-q1 \
  -f mode=import -f candidate_sha256="$CANDIDATE_SHA256" \
  -f source_commit="$C" -f draft_release_id="$DRAFT_RELEASE_ID"
```

13. After a green import, record the remote receipt and
commit Q2. Record four bindings now; do not record
`promotion-dry-run/1` here: its check-run is published by
the dry-run dispatch in step 14 (a later
remote-execution step), so dispatch dry-run before
recording its check binding
(step 15). Fetch the
immutable import coordinates (the signer commit is Q1,
the ref the import ran at):

```sh
gh run list -w release.yml
RUN_ID=<import run id from the listing above>
REPO_ID=$(gh api repos/<OWNER>/<REPO> -q .id)
gh api repos/<OWNER>/<REPO>/actions/runs/$RUN_ID/artifacts \
  -q '.artifacts[]
      | select(.name == "candidate-'"$CANDIDATE_SHA256"'")
      | "\(.id) \(.digest)"'
```

That prints `<artifact_id> sha256:<zip digest>`; keep
both. Download the stored set for the custody digest:

```sh
gh run download "$RUN_ID" -n "candidate-$CANDIDATE_SHA256" \
  -D /tmp/stored-$CANDIDATE_SHA256
CUSTODY_SHA256=$(sha256sum \
  /tmp/stored-$CANDIDATE_SHA256/custody.json | cut -d' ' -f1)
```

Assemble `packaging/qualifications/remote.json`
(schema `memveil-remote-custody/1`, canonical bytes)
from these values: `candidate_sha256`, `source_commit`
(C), `repository` (`<OWNER>/<REPO>`), `repository_id`,
`run_id`, `artifact_id`, `artifact_sha256` (the zip
digest without the `sha256:` prefix), `signer_commit`
(Q1), `custody_sha256`, and `checks`: one signed
binding per check published so far
(`tampered-payload/1`, `independent-attestation/1`,
`required-checks/1`, `no-overwrite/1`), each carrying
its published check-run ID, run ID, and head SHA (Q1,
the ref it was published against), the signed receipt
over its offline inputs, the inputs, the base64
signature (`ssh-keygen -Y sign` with namespace
`memveil-candidate`, as in step 6), and the public
key. Promote re-checks every binding against the live
check-runs API: each run must be completed and
successful, on the bound head SHA, from the
github-actions app, under the bound run. The four
check-runs above are published out of band today; the
dry-run check-run is published by the step-14 dispatch
instead. The exact contract for all of them is the one
`verify_remote_checks` enforces. Commit the receipt as
Q2 on a second frozen branch:

```sh
git add packaging/qualifications/remote.json
git commit -m "Record remote custody for $CANDIDATE_SHA256"
Q2=$(git rev-parse HEAD)
git diff --name-only "$C..$Q2"
git push origin HEAD:release-q2
```

The diff must list exactly the four qualification
paths (the Q1 three plus `remote.json`).

14. Dispatch dry-run with the ref at Q2, passing the
recorded import IDs:

```sh
gh workflow run release.yml --ref release-q2 \
  -f mode=dry-run -f candidate_sha256="$CANDIDATE_SHA256" \
  -f source_commit="$C" \
  -f import_run_id="$RUN_ID" \
  -f import_artifact_id="$ARTIFACT_ID"
```

Dry-run consumes only the recorded import coordinates
from Q2's `remote.json` (run, artifact, signer, custody)
and ignores the check bindings; promote enforces the
bindings, so four suffice here.

15. After the dry-run dispatch is green, record the
provisional dry-run receipt and carry it forward. The
dry-run ran at Q2, so the check-run named exactly
`promotion-dry-run/1` carries head SHA Q2. That
check-run is published by the dry-run dispatch at
Q2: select it by its exact check name, never the
dispatch's native
`dry-run` job check (promote re-checks the name
against the binding and rejects any other check):

```sh
gh run list -w release.yml
DRY_RUN_ID=<dry-run run id from the listing above>
gh api repos/<OWNER>/<REPO>/commits/$Q2/check-runs \
  -q '.check_runs[]
      | select(.name == "promotion-dry-run/1")
      | "\(.id) \(.head_sha) \(.details_url)"'
```

That prints the check-run ID, its head SHA, and its
details URL; keep the numeric check-run ID once the
head SHA reads Q2 and the details URL sits under run
$DRY_RUN_ID. That check producer runs as a later
remote-execution step, so Q3 awaits that evidence:
finalize Q3 only after this check-run exists and is
green. Write the provisional receipt beside the
scratch evidence (kept under ignored `dist/`, never
committed as is): the check-run ID, the run ID, head
SHA Q2, the signed receipt over the dry-run's offline
inputs, the inputs, the base64 signature
(`ssh-keygen -Y sign` with namespace
`memveil-candidate`, as in step 6), and the public
key.

16. Assemble the final promotion evidence: the same
import coordinates with all five check bindings (the
four at Q1 plus `promotion-dry-run/1` at Q2 from the
provisional receipt). Commit the finalized receipt as
Q3 on a third frozen branch:

```sh
git add packaging/qualifications/remote.json
git commit -m "Finalize promotion evidence for $CANDIDATE_SHA256"
Q3=$(git rev-parse HEAD)
git diff --name-only "$C..$Q3"
git push origin HEAD:release-q3
```

The diff must list exactly the same four
qualification paths (`remote.json` amended, still
evidence-only over C).

17. After the dry-run dispatch is green and Q3 is
frozen, tag `vX.Y.Z` on C (owner step, outside the
workflow; the version comes from `Cargo.toml` at C):

```sh
git tag "v<VERSION>" "$C"
git push origin "v<VERSION>"
```

18. Dispatch promote with the ref at Q3, the same
recorded import IDs, and `promote_authorization`
retyping the candidate digest:

```sh
gh workflow run release.yml --ref release-q3 \
  -f mode=promote -f candidate_sha256="$CANDIDATE_SHA256" \
  -f source_commit="$C" \
  -f import_run_id="$RUN_ID" \
  -f import_artifact_id="$ARTIFACT_ID" \
  -f promote_authorization="$CANDIDATE_SHA256"
```

Promote requires the tag to resolve to C, then creates
and publishes the release with the qualified notes.
Watch every dispatch (`gh run list -w release.yml`,
`gh run view <id>`); a failed stage is re-dispatched,
never patched in place.
