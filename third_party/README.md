<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Vendored dependency inputs

MemVeil consumes the clean, untagged libbpf-mojo 0.2.3 development
candidate from source commit `4a22288a397dec5158766fdfcd7a2a6691d1a9fb`
(tree `2ef224edd32f3a81c6b40236b62dee0a202443bc`). This is not a
published v0.2.3 release. ABI 1 and `libbpf_mojo.so.1` are unchanged.
Ordinary live and compiler-free clean-room gates remain pending;
source integration does not establish kernel or confidential-platform
qualification.

| Archive | SHA256 |
| --- | --- |
| `libbpf-mojo-0.2.3.tar.gz` | `c69e65d43b27fa7fbbbcf0ec827535f9193dbbbcbfc1e6604530fd01e66dd3cf` |
| `libbpf-mojo-0.2.3-source.tar.gz` | `eb5909d90ac890f7a51aff1620ed2e3b9354d5989bed15da154304154b310618` |
| `libbpf-1.7.0-source.tar.gz` | `7ab5feffbf78557f626f2e3e3204788528394494715a30fc2070fcddc2051b7b` |

`libbpf-mojo-0.2.3-source-map.json` maps runtime, first-party and
libbpf source bytes to upstream licenses, runtime providers and the
source identity. Its artifact names are local to this directory.
The prefixed `MANIFEST.json`, `build-receipt.json` and
`THIRD-PARTY-NOTICES.txt` files retain the upstream bytes verbatim;
the notice uses a `.txt` suffix to distinguish upstream attribution
from MemVeil's own documentation.

Normal MemVeil builds consume only the pinned runtime bundle, which
includes the native bridge, Mojo wrappers and public C header.
`tools/build` checks its digest against `toolchain.lock.json` and also
checks the independent libbpf header-source pin. A standalone clone or
source archive includes these inputs without sibling checkouts.

To rebuild the library independently, extract the first-party source
archive, follow its `docs/build.md` prerequisites, run `pixi install
--frozen` in that source root, and invoke its own `tools/build` and
`tools/package` wrappers. For an offline libbpf fetch, first copy the hash-verified libbpf
source archive above into the build cache at
`build/libbpf_external-prefix/src/v1.7.0.tar.gz`. CMake verifies its
pinned digest before using it. The library's `tools/test source-export
--host-only` also accepts `LMB_LIBBPF_SOURCE_ARCHIVE` to seed this
source archive in its fresh standalone builds.
A local rebuild is a new artifact; it does not acquire the supplied
bundle's hashes or qualification.

The source map covers all first-party library source and the exact
libbpf source used by the bridge. GCC and zlib source origins and build
recipes are retained in the upstream notices; their source archives
are not included here. Modular runtime libraries retain their provider
license and redistribution warning, and their proprietary source is
not included. These records preserve attribution and known limits;
they do not establish legal or publication qualification.
