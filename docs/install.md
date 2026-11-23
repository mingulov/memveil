<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# MemVeil installed packages (.deb and .rpm)

Third-party system packages for Debian/Ubuntu (`.deb`) and
Fedora (`.rpm`). Both install the same FHS layout, so every
installed run needs zero flags and zero environment: BPF
objects are embedded in the binary with the loader
statically linked, profiles resolve from the installed
share dir, and
`qualify` receipts land in the state dir. The
[bundle flow](quickstart.md) stays available for machines
without package installs.

| Path | Contents |
|---|---|
| `/usr/bin/memveil` | The CLI (RUNPATH `$ORIGIN/../lib/memveil`) |
| `/usr/lib/memveil/` | Private closure: the vendored libgcc plus BPF inspection objects |
| `/usr/share/memveil/profiles/` | Profile manifest plus shipped profiles |
| `/usr/share/memveil/docs/` | This manuals tree plus the worked example |
| `/usr/share/doc/memveil/` | Copyright, licenses, and notices |
| `/usr/share/man/man1/` | `memveil.1` plus one page per verb |
| completions dirs | Static bash and zsh completions |
| `/var/lib/memveil/receipts/` | Empty state dir; `qualify` publishes here |

No maintainer scripts run at install, no setuid bits or file
capabilities ship, and no collection runs until you invoke
it. The private libraries under `/usr/lib/memveil/` serve
only this package's RUNPATH: the `.rpm` disables
auto-provides so they never satisfy other packages, and
both formats keep system dependencies manual. The payload
ships only its binary, BPF objects, and the vendored
libgcc, with the Aya loader statically linked, so it needs
neither libelf nor zlib from the system: `libc6 >= 2.35`
on Debian and `glibc >= 2.35` on Fedora, derived from the
staged bytes and currently set by the pinned Debian
libgcc's highest numeric GLIBC need (libgcc-s1
14.2.0-19, GLIBC_2.35, no ABI nodes; see
packaging/libgcc/PROVENANCE.txt). The pinned provider
is deliberate: the build-host toolchain libgcc needs
GLIBC_ABI_GNU2_TLS, which would raise the floor to 2.40
and refuse still-compatible userlands, while the payload
needs only twelve ancient _Unwind_* symbols any libgcc
since GCC 4.2 (2007) provides.
On a userland older than the floor the install fails
closed at install time instead of breaking at load (Debian
bookworm ships libc6 2.36, above the floor).

## .deb: install, use, uninstall

Install with no `--force` (the unforced install proves the
`Depends` resolves on your system):


    sudo dpkg -i memveil_0.2.0-1_amd64.deb
    dpkg -s memveil            # Status: install ok installed
    dpkg --verify memveil      # empty output, exit 0


Then run with zero flags. `doctor` is passive and needs no
privilege; `record` and `qualify` need privilege for live
collection:


    memveil doctor
    sudo memveil record --output /tmp/cap1 --duration 5
    memveil report --format text /tmp/cap1


Expected: `doctor` prints one environment report (exit 0
ready, 3 unavailable); `record` writes a capture directory;
`report` replays it offline. Machine-local qualification
(`memveil qualify`) needs a bound document authored for
this host (see the [bound-reference recipe](profiles.md));
the bundle ships reference profiles only.
Pick `--profile` from the installed profiles (list
`/usr/share/memveil/profiles/`); on a host no profile
covers, `record` refuses with exit 3 and the exact cause,
leaving no capture directory.

Uninstall and confirm nothing remains:


    sudo dpkg -r memveil
    dpkg -s memveil            # not installed, exit 1
    ls /usr/lib/memveil /usr/share/memveil /var/lib/memveil
                               # all absent


Receipts you published are runtime state, not package
files: remove `/var/lib/memveil/receipts/*.json` before
uninstalling if you qualified this host, else the
directory stays behind with your receipts.

## .rpm: build, install, use, uninstall

Build with real `rpmbuild` from a source tree with the
contributor toolchain from [build](build.md) plus
`rpmbuild`:


    cargo build --release --locked
    python3 scripts/package-rpm.py --out dist


Expected: `Wrote: dist/memveil-0.2.0-1*.x86_64.rpm`
(the release may carry a distro suffix on Fedora
builders). The packager assembles its Source0 from the
owning checkout (tracked plus unignored-untracked files,
never a parent's set) and refuses foreign or changed
source inputs; no build fallback is permitted.

Install on Fedora (dependency resolution proves `Requires`
holds on the target distro):


    sudo dnf install ./memveil-0.2.0-1*.x86_64.rpm
    rpm -q memveil            # memveil-0.2.0-1...
    rpm -V memveil            # empty output, exit 0


Use exactly like the `.deb` (same layout, same zero-flag
verbs): `memveil doctor`, then `memveil qualify --output`
with `--profile`, `memveil record --output`, and offline
`memveil report --format`. Uninstall and confirm:


    sudo dnf remove memveil
    rpm -q memveil            # package memveil is not installed
    ls /usr/lib/memveil /usr/share/memveil /var/lib/memveil
                               # all absent


Fedora container images set `tsflags=nodocs`, which skips
the man pages and license texts at install; real Fedora
installs ship them. Pass `--setopt=tsflags=` to `dnf
install` in a container to prove the full payload.

## Manual rpm gate (no docker)

When the containerized `rpm-journey` lane cannot run, the
same flow by hand is the gate. On the build host, run the
build above, then on (or in) a Fedora target run install,
`rpm -V`, `memveil version`, zero-flag `memveil doctor`,
`ldd` showing only the vendored libgcc plus host libc,
zero-env `memveil record`, privileged
`memveil qualify` (receipt under
`/var/lib/memveil/receipts/` on a qualifying host, else a
past-resolution exit 3), uninstall, and the residue check.
Expected outputs are the ones inline above; every step
must pass with no `--bridge`, `--object`, or
`--profiles-dir` anywhere. Record the `.rpm` sha256, the
Fedora release, and the qualify branch (receipt or
refusal) with the result.

## Overrides

`--profiles-dir DIR` still selects another profiles tree
for development; receipts then stay beside it at
`DIR/receipts/`, and `record` and `doctor` must use the
same flag to see them. Only the installed
`/usr/share/memveil/profiles` maps to
`/var/lib/memveil/receipts`. `--bridge` and `--object`
likewise select non-shipped artifacts explicitly;
without them the embedded objects and the linked loader
run with no environment (under `sudo` the environment is
ignored by design). See [support](support.md) for the
capability envelope and [build](build.md) for the
toolchain.
