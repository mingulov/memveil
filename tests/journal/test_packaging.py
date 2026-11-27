#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Journal packaging closure: declarations only (no bundle built here).

Ports the old asset-declaration checks to the Rust packagers: the
journal BPF object and the candidate profile must be declared in
every payload list, and the candidate must stay unadmitted with null
runtime bindings. Full bundle/deb/rpm closure (fresh build, real
staging, whole-payload gates) belongs to final integration, which
also owns the native channel wiring these declarations await: the
build script, the embedded-object table, and the payload gate still
pin the three ordinary channels (tracked with the wiring change,
not edited here).

Counts, reconciled explicitly: the payload gate covers the engine
binary plus one entry per BPF object in each of the three packages,
so four declared objects close at 5 x 3 = 15 entries. The frozen
fixture shape is separate: 13 scenarios with 12 reports (the
`duplicate` scenario carries no report). Neither count implies the
other; do not hardcode one where the other belongs.
"""
import json
import re
import sys
from importlib.machinery import SourceFileLoader
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TARBALL = ROOT / "scripts" / "package-tarball.py"
DEB = ROOT / "scripts" / "package-deb.py"
SPEC = ROOT / "packaging" / "rpm" / "memveil.spec"
OVERRIDES = ROOT / "packaging" / "deb" / "lintian-overrides"
PROFILE = ROOT / "profiles" / "journal-candidates" / \
    "linux-7.0.14-x86-journal-provisional.json"
JOURNAL_OBJECT = "conversion_journal.bpf.o"


def fail(message):
    print("test_packaging: %s" % message, file=sys.stderr)
    sys.exit(1)


def load(path, name):
    try:
        return SourceFileLoader(
            name, str(path)).load_module()
    except Exception as exc:  # noqa: BLE001 -- fail closed with the cause
        fail("cannot import %s: %s" % (path, exc))


def main():
    tarball = load(TARBALL, "journal_tarball")
    channels = dict(tarball.CHANNELS)
    if channels.get("journal") != JOURNAL_OBJECT:
        fail("tarball CHANNELS lacks the journal object: %r"
             % (tarball.CHANNELS,))
    if len(tarball.CHANNELS) != 4 or len(set(tarball.CHANNELS)) != 4:
        fail("tarball CHANNELS must list exactly 4 unique channels")
    deb = load(DEB, "journal_deb")
    if JOURNAL_OBJECT not in deb.BPF_OBJECTS:
        fail("deb BPF_OBJECTS lacks the journal object")
    if len(deb.BPF_OBJECTS) != 4 or len(set(deb.BPF_OBJECTS)) != 4:
        fail("deb BPF_OBJECTS must list exactly 4 unique objects")
    spec = SPEC.read_text()
    if JOURNAL_OBJECT not in spec:
        fail("rpm spec lacks the journal object")
    overrides = OVERRIDES.read_text()
    if JOURNAL_OBJECT not in overrides:
        fail("lintian overrides lack the journal object")
    if len(re.findall(r"binary-from-other-architecture", overrides)) != 4:
        fail("lintian overrides must name exactly 4 BPF objects")
    # Payload inventory: binary + one BPF object each, in all three
    # packages. The declaration lists above are the source; the
    # compiled payload gate pins the pre-journal 12 until its own
    # authorized repair lands (tracked with the wiring change).
    entries = (1 + len(deb.BPF_OBJECTS)) * 3
    if entries != 15:
        fail("payload inventory closes at %d entries, want 15" % entries)
    staged = sorted("bundle/bpf/%s" % name for name in deb.BPF_OBJECTS)
    if ("bundle/bpf/%s" % JOURNAL_OBJECT) not in staged:
        fail("journal object missing from the bundle inventory")
    # Candidate profile: shipped by the recursive profiles stagers,
    # unadmitted with null runtime bindings.
    if not PROFILE.is_file():
        fail("candidate profile missing: %s" % PROFILE)
    try:
        profile = json.loads(PROFILE.read_text())
    except ValueError as exc:
        fail("candidate profile is not JSON: %s" % exc)
    if profile.get("status") != "unadmitted":
        fail("candidate profile must stay unadmitted")
    for key in ("config_sha256", "btf_sha256", "object_sha256"):
        if profile.get(key) is not None:
            fail("candidate profile must leave %s null" % key)
    for path, needle in (
            (TARBALL, 'for base, dirs, files in os.walk(os.path.join(root, "profiles"))'),
            (DEB, "os.path.join(bundle, \"profiles\")")):
        if needle not in path.read_text():
            fail("%s no longer stages profiles recursively" % path.name)
    if 'cp -rp "$B"/profiles/*' not in spec:
        fail("rpm spec no longer stages profiles recursively")
    # Fixture shape, reconciled (not equated) with the payload count:
    # 13 scenarios, 12 reports, `duplicate` reportless.
    scenarios = sorted(p.name for p in (ROOT / "tests" / "fixtures" / "journal").iterdir()
                       if p.is_dir())
    if len(scenarios) != 13:
        fail("fixture scenarios number %d, want 13" % len(scenarios))
    reports = [name for name in scenarios
               if (ROOT / "tests" / "fixtures" / "journal" / name / "report.json").is_file()]
    if len(reports) != 12 or "duplicate" in reports:
        fail("fixture reports must be 12 with `duplicate` reportless")
    print("journal packaging: 15-entry payload declared (bpf object + "
          "candidate profile); 13-scenario / 12-report fixture shape "
          "reconciled; candidate unadmitted")


if __name__ == "__main__":
    main()
