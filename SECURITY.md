<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Security policy

## Supported versions

A release is supported until the next minor release
supersedes it (see [policy](docs/policy.md)). The
0.1.x line are development prereleases; end of life
is announced in the release notes of the superseding
release.

## Reporting a vulnerability

Report privately to the maintainer address recorded
in the package metadata (Debian control `Maintainer`
field; currently Denis Mingulov
<denis@mingulov.com>). Do not file public issues
for unpatched disclosures.

Each report gets a private fix with a regression
test, a release-notes entry crediting the reporter
unless they decline, and a new release; the
advisory states affected versions and the upgrade
path. Response-time promises start with the first
stable release; until then this route is
best-effort.

## Scope notes

Captures never contain payloads, keys, PINs,
content hashes, raw addresses, full command lines,
or environment dumps ([privacy](docs/privacy.md)),
so a leaked capture directory exposes measurement
metadata, not secrets. The product performs no
attestation and renders no host-access verdicts;
do not report those absences as vulnerabilities.
