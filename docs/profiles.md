<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Bound-reference authoring: from doctor to qualify

A bound reference is a semantic profile document that names
one exact host identity — kernel image, config, BTF,
tracepoint format, BPF objects, and hook semantics — so
`memveil qualify` can prove that host and mint a
machine-local `local-auto` receipt. Hosts covered by a
shipped reference need no authoring: an unbound reference
admits them through the live judgment, which probes the
running kernel instead of comparing recorded hashes
(step 1). This recipe walks the whole journey on a fresh
eligible host: passive `doctor` output, evidence capture,
binding computation, document authoring, manifest
registration, qualify, reuse, and stale-input refusal. Every command below was checked
against its wrapper help. The qualify planning
refusals in step 7 were observed live; the receipt
diagnostics in steps 8 and 9 were observed through
hand-written receipts exercising the verify path,
not minted receipts; the layout-drift strings in
step 4 are unit-test-pinned shapes rather than live
observations; and the success line in step 7 is
quoted from the implementation. The successful
smoke, reuse, and refresh journey still awaits
confirmation on an admitted host.

Status words stay fixed. A document you author is
`reference-unvalidated` with `candidate` capabilities; only
a `local-auto` receipt from `memveil qualify` admits it on
the bound host, and nothing in this recipe mints or claims
`validated`. A matching kernel release alone never admits a
host: the bindings below refuse anything else. Keep three
kinds of value distinct throughout: raw identity hashes
recorded in the document, observed counters rendered by
reports, and support claims, which need the exact packaged
artifact and its test evidence
(`support.md`).

## Prerequisites

- A MemVeil binary and its packaged BPF objects (bundle or
  source build).
- The source helpers `tools/probe-inventory` (read-only
  evidence capture) and `tools/validate-schemas` (shape
  oracle) from a source checkout.
- Standard tools: `sha256sum`, `gunzip`, `python3`.
- Root for reading tracefs format files and the kernel
  image, and for running `memveil qualify`.

## 1. Inspect the fresh host

Start unprivileged and passive. On an x86-64 host running
`7.0.0-38-generic` with the shipped profiles:

    ./build/memveil doctor

prints, in part:

    kernel: 7.0.0-38-generic x86_64 (floor 6.0: yes)
    profile: linux-x86_64-7.0-reference (reference-unvalidated)
    profile-detail: profile linux-x86_64-7.0-reference covers this identity but is reference-unvalidated; linux-x86_64-7.0.0-34-generic identity mismatch: revision
    capabilities:
      attempt-trace: unknown - tracepoint swiotlb:swiotlb_bounced denied (privilege)
        fix: re-run with elevated privileges (root)
      mapping-lifecycle: unknown - available_filter_functions denied (privilege)
        fix: re-run with elevated privileges (root)
      copy-actual: unknown - available_filter_functions denied (privilege)
        fix: re-run with elevated privileges (root)
    privilege: euid 1001, denied: /sys/kernel/tracing/events/swiotlb/swiotlb_bounced/id /sys/kernel/tracing/events/swiotlb/swiotlb_bounced/format
    verdict: unavailable

with exit 3. Read it as: the kernel clears the 6.0 floor;
the shipped reference covers this kernel by identity but
is unvalidated; the narrow `7.0.0-34-generic` profile does
not cover this revision; and tracefs plus the ftrace
function list are unreadable without privilege, so every
capability is unknown rather than refused. Re-run
passively as root for the full picture:

    sudo ./build/memveil doctor

    profile: linux-x86_64-7.0-reference (reference-unvalidated)
    capabilities:
      attempt-trace: available - live-verified under reference profile linux-x86_64-7.0-reference
      mapping-lifecycle: available - live-verified under reference profile linux-x86_64-7.0-reference
      copy-actual: available - live-verified under reference profile linux-x86_64-7.0-reference
    privilege: euid 0
    verdict: ready

Exit 0: the unbound reference admits this host through
the live judgment, which verifies the tracepoint
format, hook signatures, and attachability on the
running kernel. Recording works here with no authoring.
The rest of this recipe covers the harder case:
capturing evidence, computing narrow bindings, and
authoring a bound reference for a host the shipped
references do not cover — plus the `memveil qualify`
step that mints a machine-local `local-auto` receipt
pinning a document to one host.

## 2. Capture the evidence inventory

`tools/probe-inventory` reads the live host's evidence
sources without loading anything or changing anything.
Plain output is a JSON inventory; `--emit-fixture DIR`
writes a fixture tree mirroring the evidence root plus a
`meta.txt` header and a `blobs.txt` disposition list:

    ./tools/probe-inventory --emit-fixture /tmp/fix1

`meta.txt` records the arch, release, euid, and denied
paths the reader needs:

    arch=x86_64
    release=7.0.0-38-generic
    euid=1001
    denied=/sys/kernel/tracing/events/swiotlb/swiotlb_bounced/format,/sys/kernel/tracing/events/swiotlb/swiotlb_bounced/id

while `blobs.txt` records binary dispositions without
copying bytes by default:

    /boot/config-7.0.0-38-generic=ok:308501
    /proc/config.gz=absent:?
    /sys/kernel/btf/vmlinux=ok:7067009

Absent and denied stay distinct: `absent` means the source
does not exist here, `denied` means it exists but this
user cannot read it. Emission refuses an existing
destination, so a re-emit can never mix fresh evidence
with stale files. Add `--include-blobs` to copy BTF and
config bytes into the fixture for exact local
reproduction.

## 3. Compute the narrow bindings

The document's `identity.source.note` carries the narrow
bindings in one fixed grammar: exact keys, fixed order,
single spaces, lowercase hex, 8 fields for attempt-only
documents (`config`, `config_src`, `btf`, `format`,
`object`, `image`, `image_bid`, `ring_bytes`), 12 with the
appended `lc_object`, `lc_ring_bytes`, `cp_object`, and
`cp_ring_bytes` bindings for the extra channels. Each
field pins one exact source:

| Field | Source and hash rule |
|---|---|
| `config` | `sha256:` of `/proc/config.gz` gunzipped, else of `/boot/config-<release>` raw |
| `config_src` | `gz` when the first source supplied the hash, else `file` |
| `btf` | `sha256:` of `/sys/kernel/btf/vmlinux` bytes |
| `format` | `sha256:` of the tracepoint `format` file bytes |
| `object` | `sha256:` of the packaged attempt BPF object bytes |
| `image` | `sha256:` of `/boot/vmlinuz-<release>` bytes |
| `image_bid` | 40 lowercase hex GNU build-id from `/sys/kernel/notes` (snippet below) |
| `ring_bytes` | `8388608` |

The recipe is checkable against the checked-in qualify
fixtures, whose note was recomputed here with plain
commands. With `H=tests/fixtures/qualify/host`:

    gunzip -c $H/proc/config.gz | sha256sum
    sha256sum $H/sys/kernel/btf/vmlinux
    sha256sum $H/sys/kernel/tracing/events/swiotlb/swiotlb_bounced/format
    sha256sum tests/fixtures/elf/ok.o
    sha256sum $H/boot/vmlinuz-7.0.0-test

yield, in order, `a5af36b0...`, `6c7ff9b3...`,
`43b8d6d5...`, `ff9109de...`, and `11a663ae...`, each
matching the corresponding `sha256:` value in the
`identity.source.note` of
`tests/fixtures/qualify/profiles/qual-ref.json`
(`config_src=gz`, `ring_bytes=8388608`). The build ID
needs its own extraction: `/sys/kernel/notes` holds
binary GNU notes, so hash tools cannot read it. This
standard-library snippet prints the first GNU build
ID (type 3, name `GNU`) as 40 lowercase hex:

    python3 - tests/fixtures/qualify/host/sys/kernel/notes <<'EOF'
    import struct, sys
    try:
        data = open(sys.argv[1], 'rb').read()
    except OSError:
        raise SystemExit('notes unreadable')
    pos, bid = 0, None
    while pos + 12 <= len(data):
        namesz, descsz, ntype = struct.unpack_from('<III', data, pos)
        pos += 12
        name_end = pos + (namesz + 3) // 4 * 4
        if name_end > len(data):
            raise SystemExit('notes unparseable')
        name = data[pos:name_end][:namesz]
        pos = name_end
        desc_end = pos + (descsz + 3) // 4 * 4
        if desc_end > len(data):
            raise SystemExit('notes unparseable')
        desc = data[pos:pos + descsz]
        pos = desc_end
        if ntype == 3 and namesz == 4 and name == b'GNU\x00':
            if descsz != 20:
                raise SystemExit('build-id malformed')
            bid = desc.hex()
            break
    if bid is None:
        raise SystemExit('no build-id note')
    print(bid)
    EOF

Against the fixture notes it prints
`0102030405060708090a0b0c0d0e0f1011121314`, the
`image_bid` recorded in `qual-ref.json`. A GNU note
with a short descriptor exits 1 with `build-id
malformed`; notes without one report `no build-id
note`, as does a trailing fragment shorter than a
12-byte header. An unreadable file reports `notes
unreadable`, while a parsed header declaring an
incomplete name or descriptor reports `notes
unparseable`; any of those leaves the binding
uncheckable, and qualify refuses with `binding
failed: image_bid uncheckable` (exit 3). Assemble
the note by joining
the eight `key=value` fields with single spaces in
table order; the note must stay within 1024 bytes.
On the live host the same commands run against `/`
instead of the fixture root, with root reads for the
format file and the kernel image; the notes file is
world-readable, so the snippet needs no privilege.

## 4. Record hook evidence

Two hook kinds exist. A `tracepoint` hook records the
exact `format` file bytes in `format_text` (byte
equality, up to 65536 bytes): the checked-in fixture's
recorded text equals
`tests/fixtures/layout/ok.format` byte for byte. The
collector additionally probes the live layout before
it trusts the record. The `common_type` anchor must
match exactly, and `dev_name`, `size`, and `force`
must keep their pinned type spellings and widths;
their offsets are probed into the load-time table, so
offset-only moves are admitted and flagged rather
than refused. Any retype, resize, missing or
duplicate field, unparseable line, anchor drift,
overlap, or cap breach refuses naming its class
(for example `missing field force` or
`field force: want type bool, live u8`, both
unit-test-pinned shapes rather than live
observations):

| Field | Pinned type | Width |
|---|---|---|
| `common_type` | `unsigned short` | 2 at 0 (anchor) |
| `dev_name` | `__data_loc char[]` | 4, offset probed |
| `size` | `size_t` | 8, offset probed |
| `force` | `bool` | 1, offset probed |

A `tracing` hook (`fentry`/`fexit`) records the kernel
function name and its frozen signature in single-line
`<ret> <name>(<params>)` form, exactly as the
[frozen signatures](lifecycle-hooks.md#signatures)
spell it. `memveil qualify` compares that text against
the live BTF prototype during planning and refuses on
any mismatch, so a copied signature from another kernel
fails loudly instead of attaching to unproven
semantics. Extra channels additionally require exactly
the frozen hook set per capability; see
`lifecycle-hooks.md` for the membership rules.

`identity.source` makes the document source-backed: set
`origin` to where the hook semantics were verified
(`distro` names a distribution kernel source tree),
`revision` to the kernel release the bindings pin, and
use `notes` to cite the inspected source tree. The
revision must equal the running release later, or
receipt verification refuses.

## 5. Write the document

Author one JSON file per kernel, profile schema `0.1.1`,
`status` always `reference-unvalidated`, capabilities
`candidate` (or `unsupported` when the document carries
no source for a channel). The checked-in
`tests/fixtures/qualify/profiles/qual-ref.json` is a
complete specimen of this shape. An attempt-only
document for a new host follows the same skeleton:

    {
      "schema_version": "0.1.1",
      "profile_id": "my-host",
      "status": "reference-unvalidated",
      "identity": {
        "arch": "x86_64",
        "min_kernel": "7.0",
        "source": {
          "origin": "distro",
          "revision": "7.0.0-38-generic",
          "note": "config=sha256:... config_src=file btf=sha256:... format=sha256:... object=sha256:... image=sha256:... image_bid=... ring_bytes=8388608"
        },
        "note": "Narrow identity for this host; bindings refuse every other identity."
      },
      "hooks": [
        {
          "name": "swiotlb:swiotlb_bounced",
          "kind": "tracepoint",
          "id_path": "/sys/kernel/tracing/events/swiotlb/swiotlb_bounced/id",
          "format_path": "/sys/kernel/tracing/events/swiotlb/swiotlb_bounced/format",
          "format_text": "<exact format file bytes>",
          "note": "Exact tracepoint format bytes recorded during authoring; admission requires byte-equality."
        }
      ],
      "capabilities": [
        {
          "id": "attempt-trace",
          "status": "candidate",
          "hooks": ["swiotlb:swiotlb_bounced"],
          "reason": "Candidate collection source; availability is checked passively, semantics are unproven until qualify."
        }
      ],
      "notes": ["Authored from the <release> source tree; inspection is not qualification evidence."]
    }

Never write `status` as `validated`: that promotion
belongs to the evidence gates behind the shipped narrow
profile, never to this recipe. Check the shape with the
independent oracle before registering:

    ./tools/validate-schemas --check-profile my-host.json

    profile OK: my-host.json

A malformed document fails instead, for example:

    invalid: missing-required: profile lacks ['capabilities', 'hooks', 'identity', 'profile_id', 'schema_version', 'status']

with exit 1. Shape validity is not semantic proof: only
`memveil qualify` checks bindings and signatures
against the live host.

## 6. Register the document

Only manifest-listed documents are visible, and the
first covering document wins: list the new file
first, ahead of the shipped entries. Copy the
checked document in, then rewrite the manifest with
the new file on top (one file name per line, no
blank lines, no duplicates, plain names only).
Then `doctor`, automatic `record`, and live `top`
must all use the same `--profiles-dir` when it is
not the default:

    cp my-host.json "$PWD/profiles/my-host.json"
    { echo my-host.json; cat "$PWD/profiles/manifest.txt"; } > /tmp/manifest.new \
        && mv /tmp/manifest.new "$PWD/profiles/manifest.txt"

Registration is what makes the document selectable. With
`my-host.json` present but unlisted, `doctor` keeps
selecting the shipped reference:

    profile: linux-x86_64-7.0-reference (reference-unvalidated)

while after listing it first, `doctor` selects it:

    profile: my-host (reference-unvalidated)

Appending instead would leave the new file behind
the shipped covering reference, so `doctor` would
keep selecting the reference.

Manifest mistakes refuse loudly instead of guessing.
A blank line:

    memveil doctor: cannot load profiles: ValidationError(what=manifest, message=blank line)

and a duplicate entry:

    memveil doctor: cannot load profiles: ValidationError(what=manifest, message=duplicate entry)

both exit 2.

## 7. Qualify the host

`memveil qualify` plans first and attaches never on a
refused plan. Planning parses the capability request,
checks the kernel floor, resolves the document,
parses its note, and compares every binding and every
tracing-hook signature against the live host. Only an
accepted plan runs the 3-second smoke capture and
publishes the `local-auto` receipt. From a source
checkout, point at the source-build artifacts
explicitly: discovery searches the bundle and system
locations, while a source build places its objects
under `build/bpf` and its bridge under `build/deps`,
so a bare invocation refuses with `no object: pass
--object PATH` (exit 3) before planning. From the
checkout root, with a fresh unused output directory
(every attempt needs its own; reuse refuses, see
step 9):

    sudo ./build/memveil qualify --output /tmp/q1 \
        --object build/bpf/swiotlb_attempt.bpf.o \
        --bridge build/deps/lmb/lib/libbpf_mojo.so.1 \
        --profile "$PWD/profiles/my-host.json"

On success the receipt lands under
`profiles/receipts/` beside the binary (or under
`--profiles-dir DIR/receipts/` when given) and the verb
prints `qualify: local-auto <profile> caps=...` with
exit 0. That success line is quoted from the
implementation; the successful smoke still awaits
confirmation on an admitted host. Every planning
refusal below was observed; each exits 3 with no
receipt written and nothing attached.

An unbound document refuses on its note. The shipped
reference and any free-text note fail the grammar:

    memveil qualify: profile linux-x86_64-7.0-reference bindings unparseable: narrow note: want 8 or 12 fields

meaning: the note is not 8 or 12 grammar fields, so
there are no bindings to check. Fix by authoring the
note in step 3. Other grammar failures name the field
(`narrow note: bad btf`, `narrow note: bad image_bid`,
and so on).

A stale document refuses on the first drifted binding
in grammar order. A document bound to other bytes than
the live host reports, for example:

    memveil qualify: binding failed: config_src mismatch

meaning: the live config source differs from the
recorded one (here the host serves `file` while the
document records `gz`), so the host is not the bound
one. Refresh the bindings from the live host (step 9)
and re-run. A single flipped format byte reports
`binding failed: format mismatch` the same way; an
unreadable live source reports `binding failed: <key>
uncheckable` instead, which asks for privilege or a
fixed path rather than a rebind.

Unproven hook semantics refuse on the signature. A
document whose bindings match the live host but whose
frozen signature differs from live BTF reports:

    memveil qualify: fexit:swiotlb_tbl_map_single: signature mismatch

meaning: the recorded prototype is not this kernel's
prototype, so the hook stays unproven. An unknown
function or a malformed frozen text refuses with the
hook name and that cause instead. No kernel-version
match overrides any of these: only exact bindings plus
proven signatures reach the smoke.

Request mistakes refuse before any host check:

    memveil qualify: unknown --profile: definitely-not-a-profile
    memveil qualify: bad capability list
    memveil qualify: cannot load profiles: EvidenceError(code=6, message=manifest.txt: cannot open)

meaning, in order: no such document id or path; the
`--capability` list is malformed (comma-separated,
no spaces); the profiles directory has no readable
manifest. All three are usage errors in the
invocation, not verdicts about the host.

## 8. Reuse the qualified host

After `memveil qualify` mints the receipt, re-running
`doctor` against the same profiles directory keeps
reporting the document as explicitly bridge-unchecked
with exit 3: the passive path performs no bridge
binding, so only `record` and live `top` — which
verify bridge admission at every start — admit the
receipt as `local-auto`. With the bound reference
registered, privileged `doctor` now reports the
candidate state and the next action:

    profile: my-host (reference-unvalidated)
    profile-detail: profile my-host covers this identity but is reference-unvalidated; my-host receipt bridge unchecked: no binding performed on this path
      attempt-trace: unknown - candidate under reference-unvalidated profile my-host: hooks present, semantics unproven
        fix: run memveil qualify for local-auto, or await validated evidence
    verdict: unavailable

The receipt diagnostic above was observed through a
hand-written receipt exercising the verify path, not
a minted receipt. `record` and live `top` reuse the
receipt through the same `--profiles-dir`; an
explicit `--profile` that fails binding refuses
instead of recording an unverified channel. Live
reuse of a minted receipt still awaits confirmation
on an admitted host. See `quickstart.md` for the
record and replay commands.

## 9. Refresh after any change

Any kernel, object, bridge, or profile change
invalidates the binding. `doctor` still names the
receipt mismatches its passive checks can see. A
kernel upgrade leaves the old receipt behind:

    profile-detail: profile my-host covers this identity but is reference-unvalidated; my-host receipt names another kernel

while refreshing the document's bindings without
re-qualifying leaves the receipt disagreeing with the
note:

    profile-detail: profile my-host covers this identity but is reference-unvalidated; my-host receipt bindings differ from note

Both diagnostics above were observed through
hand-written receipts exercising the verify path,
not minted receipts. A rebuilt object fails at
record start with the object key named
(implementation-derived: record re-verifies
bindings at every start). The refresh procedure is
always the same: recompute the bindings from the
new host (step 3), update the document (step 5),
re-check its shape, and re-run `memveil qualify`
with a new unused `--output` directory (step 7) —
never reuse the previous smoke directory. Reusing
an output directory refuses with `output exists:
output exists` (exit 3) before attaching, so the
stale receipt is never refreshed. Never hand-edit
a receipt: receipts are minted evidence.
Verification compares the schema, profile, kernel,
bindings, object hashes, and bridge hash against
the document and the live host, so edits there
fail; `created_ns`, the version string, and the
workload note are shape-checked audit context,
and whitespace changes stay valid. A stale receipt
loses
`local-auto` admission until qualify re-proves the
host.

## Refusal catalog

| Refusal | Meaning | Fix |
|---|---|---|
| `bindings unparseable: narrow note: ...` | note is not the 8/12-field grammar | author the note (step 3) |
| `binding failed: <key> mismatch` | live value differs from the binding | refresh bindings, re-qualify |
| `binding failed: <key> uncheckable` | live source unreadable here | privilege or path fix |
| `<hook>: signature mismatch` | frozen text is not live BTF | record this kernel's prototype |
| `<hook>: frozen signature malformed` | frozen text is not `<ret> <name>(...)` | repair the signature spelling |
| `unknown --profile: ...` | no such id or path | correct the argument |
| `bad capability list` | malformed `--capability` | comma-separated, no spaces |
| `cannot load profiles: ...` | missing/unreadable manifest dir | fix dir and manifest |
| `manifest ... blank line` | blank manifest line | remove it |
| `manifest ... duplicate entry` | repeated manifest file | list once |
| `receipt names another kernel` | receipt kernel is not this kernel | re-qualify after upgrade |
| `receipt bindings differ from note` | doc refreshed past the receipt | re-qualify |
| `receipt bridge unchecked: ...` | passive path binds no bridge | use record/live top |
| `no object: pass --object PATH` | no BPF object discovered | pass the object path |
| `output exists: output exists` | output dir already holds a capture | use a fresh unused `--output` dir |

## Boundaries

- Raw identity hashes, observed counters, and support
  claims are different things. A recorded hash proves
  only that the bytes matched; a rendered counter
  summarizes captured events; a support claim needs
  the exact packaged artifact plus its test evidence.
- Kernel-version matching promotes nothing. The floor
  check is eligibility only; admission needs the full
  binding, proven hook semantics, and a verifying
  receipt.
- A wrong tracepoint layout is a precise
  unsupported-layout outcome naming the field and
  class, never silent acceptance of misread bytes;
  offset-only moves are the one tolerated drift,
  probed into the load-time table and flagged.
- Receipts never claim `validated`, and this recipe
  never mints that grade. The one shipped narrow
  profile earned its status through VM-gate evidence
  behind `tools/emit-gate-profiles`, the maintainer
  path for that gate kernel only; new kernels follow
  this recipe and qualify machine-locally.
