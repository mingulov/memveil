<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Evolution and support policy

This policy covers releases from v0.1.0. It states how
long formats, kernels, packages, and receipts stay
supported, how each evolves, and how to report a
vulnerability. Every `vX.Y.Z` named here must exist as
a git tag (pinned by the docs gate); future releases
are named without the `v` prefix until they are tagged.

## Schema and format windows

Each schema family versions independently; the frozen
set in [format compatibility](format-compatibility.md)
is the only supported input (events 0.1.1/0.1.2,
profiles 0.1.1/0.1.2, session 0.1.1/0.1.2/0.1.3/0.1.4,
report output-only 0.1.4, doctor output-only 0.1.1 (0.1.0 retained),
receipt 0.1.0). A shipped version stays accepted
until a later release removes it; removal is
announced in the release notes one minor version
ahead and never lands silently. The reader never
drops a version without that notice, and unknown
versions keep refusing with exit 2.

Session/report 0.1.4 implement integrity with event 0.1.2 unchanged;
session/event/report 0.2.0 are reserved for the conversion journal. Journal versions are
not implemented, accepted inputs or produced outputs yet. See the planned
[integrity/recovery contract](capture-integrity.md) for the normal/strict
exit table and legacy quality demotion. No schema number may be reused.

Current reader compatibility per capture generation:

- 0.1.1 captures (session 0.1.1, events 0.1.1):
  read green; relations expand
  legacy-conservatively.
- 0.1.2 captures (session up to 0.1.2, events up
  to 0.1.2): read green, including the true-only
  copy markers.
- 0.1.3 captures (session 0.1.3): read green,
  including the record verdict and stop keys.

The adversarial CLI gate reads one fixture per
accepted session generation plus the event
0.1.2 marker fixture, and refuses the unknown
major; the oracle validates every one of them
independently.

## Qualify receipts: no expiry date, binding-bound life

Receipts carry no time expiry: `created_ns` records
when qualification ran, and nothing reads it as a
deadline. A receipt admits `local-auto` only while
every checked binding still holds. Current receipt 0.1.0 records kernel
architecture/release; config hash and source, BTF hash, trace-format hash,
kernel-image hash/build ID; profile ID; per-capability results; bridge and
requested BPF object hashes; product version and smoke workload. `record`
rechecks the applicable bindings at every start, with actual object/bridge
resolution rather than a passive load claim. The smoke workload does not
require traffic, so a receipt does not supply an independent activity oracle,
confidential-guest evidence or release qualification.

The product field is a version string, not an executable hash; profile ID
and parsed identity bindings are not a hash of the entire document. A
same-version executable rebuild or unrelated profile prose edit is therefore
not guaranteed to invalidate a receipt. Changes to checked kernel, object,
bridge or profile bindings lose admission until those bindings are refreshed
and `qualify` publishes a fresh receipt (renewal atomically replaces the
old file). Re-run qualification after every artifact upgrade regardless of
whether the old receipt would still verify. Exact packaged-artifact release
evidence is a separate requirement. Revocation is deletion: remove the
receipt from `<profiles-dir>/receipts`
(`/var/lib/memveil/receipts` for an installed
package) and the host falls back to candidate or
covering admission, or refuses. Receipts never
claim `validated`.

## Kernel cadence and the 7.4 watch

The kernel lock gains rows only through matrix
runs with oracle agreement; the
[qualification ceiling](support.md#kernel-generations)
moves from 7.3 to a newer kernel only together
with its passing row and the accompanying doc
update. Each minor release re-runs the matrix.
Between releases, the 7.4 watch is the documented
probing path: a source check (diff the five hooks
plus the tracepoint fields against the frozen
shapes) and a boot check (`doctor` plus `record`
on the new kernel). Admission without the boot
check is never a support claim. No calendar
promises a row: unrun kernels stay unqualified no
matter their version.

## Package upgrade, rollback, end of life

- Upgrade installs the newer package with the
  same commands as a fresh install (see
  [install](install.md)) and re-runs `qualify`. Checked bridge/object and
  kernel bindings detect drift; receipt 0.1.0 does not bind executable bytes.
- Rollback reinstalls the older package and
  re-runs `qualify` for the same reason; a
  rerun of a release tag never replaces
  published files (rollback is a new tag).
- A release is supported until the next minor
  release supersedes it; 0.1.x versions are
  development prereleases with no long-term
  branch. End of life is announced in the
  release notes of the superseding release.

## Capture retention

Captures are your files: the product never
deletes, moves, uploads, or phones them home.
Keep a capture as long as its conclusions
matter; delete the directory when they no
longer do. Gate and matrix evidence retention
follows [evidence retention](evidence-retention.md):
a support claim keeps its row receipts until a
newer qualified run supersedes them.

## Security response

Report vulnerabilities privately to the
maintainer address recorded in the package
metadata (Debian control `Maintainer` field;
currently Denis Mingulov
<denis@mingulov.com>). Do not file public
issues for unpatched disclosures. Each report
gets a private fix with a regression test, a
release-notes entry crediting the reporter
unless they decline, and a new release; the
advisory states affected versions and the
upgrade path. Response-time promises start
with the first stable release; until then
this route is best-effort.

## Verb and format homes

Every shipped verb's contract is its built
`--help` (the single source of truth) plus
the doc beside it; every format's contract is
its schema plus the doc beside it. Anything
without a home is removed, not shipped.

| Verb | Help | Doc home |
| --- | --- | --- |
| `record` | `record --help` | [recording selection](recording-selection.md), [profiles](profiles.md) |
| `report` | `report --help` | [format compatibility](format-compatibility.md), [oracles](oracles.md) |
| `top` | `top --help` | [quickstart](quickstart.md), [recording selection](recording-selection.md) |
| `doctor` | `doctor --help` | [support](support.md), [troubleshooting](troubleshooting.md) |
| `qualify` | `qualify --help` | [profiles](profiles.md) (bound-reference recipe), [support](support.md) |
| `bind-profile` | `bind-profile --help` | [profiles](profiles.md), [quickstart](quickstart.md) |

| Format | Schema | Doc home |
| --- | --- | --- |
| session | `schemas/session-v*.schema.json` | [format compatibility](format-compatibility.md) |
| event | `schemas/event-v*.schema.json` | [format compatibility](format-compatibility.md) |
| report | `schemas/report-v*.schema.json` | [format compatibility](format-compatibility.md), [oracles](oracles.md) |
| profile | `schemas/profile-v*.schema.json` | [profiles](profiles.md) |
| doctor | `schemas/doctor-v*.schema.json` | [support](support.md) |
| receipt | `schemas/receipt-v*.schema.json` | [profiles](profiles.md), this policy |

## Shipped licences

The product is GPL-3.0-or-later (`LICENSE`;
texts in `LICENSES/`). The BPF objects are
MemVeil's own GPL-2.0-only builds. The
runtime closure's third-party components are
listed per file with texts in
`THIRD-PARTY-NOTICES.md`: the bridge is
Apache-2.0 WITH LLVM-exception, its
statically linked libbpf 1.7.0 is
BSD-2-Clause, libgcc/libstdc++ are
GPL-3.0-only WITH GCC-exception-3.1, and
the Mojo runtime ships its own licence plus
third-party notices. This section,
`LICENSE`, `LICENSES/`, and the notices
file together are the licence answer; if
they disagree, the staged texts win.
