#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Provenance gate: licenses, pins, versions, and packager inputs.

Every first-party source file carries an SPDX identifier from a
known set with its license text staged; third-party notices name
the exact pinned bridge; the toolchain lock has no unknown
origins and agrees with the pixi manifest; product, schema, and
bridge versions stay distinct; and every static input
tools/package needs from this tree exists. Pinned-bridge bytes
(LMB_PACKAGE hash, staged license copies) are verified at pack
time, not here. Exits nonzero on the first failure.
Standard library only.

The file inventory comes from Git only when this source root
owns its Git top level; a standalone source archive (outside
any repository, or nested under an unrelated one) enumerates
the complete validated tree inventory instead, so a foreign
parent's ignore rules can never shrink the checked set.
`test_provenance.py --list-files` prints the enumerated set.
Both Git calls run with repository, index, and
configuration overrides removed from the environment,
so foreign GIT_DIR, GIT_WORK_TREE, GIT_INDEX_FILE,
or GIT_CONFIG_* values can neither spoof ownership
nor shrink the enumerated file set.
"""

import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))

sys.path.insert(0, os.path.join(ROOT, "tools"))
import source_inventory  # noqa: E402

KNOWN_IDS = {
    "GPL-3.0-or-later": "LICENSE",
    "GPL-2.0-only": "LICENSES/GPL-2.0-only.txt",
    "GPL-2.0-or-later": "LICENSES/GPL-2.0-or-later.txt",
}

CODE_SUFFIXES = (
    ".mojo", ".c", ".h", ".py", ".sh", ".md", ".yml", ".yaml",
)
CODE_BASENAMES = ("Makefile", "CMakeLists.txt", "Dockerfile")
SKIP_DIRS = ("build", "dist", ".pixi", "__pycache__", ".pytest_cache",
             ".git", ".mypy_cache")

HEX64 = re.compile(r"^[0-9a-f]{64}$")

STATIC_INPUTS = [
    "LICENSE", "THIRD-PARTY-NOTICES.md",
    "LICENSES/GPL-2.0-only.txt", "LICENSES/GPL-2.0-or-later.txt",
    "docs/quickstart.md", "docs/support.md", "docs/privacy.md",
    "examples/real-capture/events.ndjson",
    "examples/real-capture/session.json",
    "profiles/manifest.txt",
    "bpf/programs/swiotlb_attempt.bpf.c",
    "src/memveil/main.mojo", "toolchain.lock.json",
]


def check(name, cond, detail=""):
    if not cond:
        print("FAIL %s %s" % (name, detail))
        sys.exit(1)
    print("ok %s" % name)


def git_env():
    """Environment for Git calls: repository, index, and
    configuration overrides removed, so neither the
    ownership comparison nor the file set can be
    relocated or shrunk from the environment."""
    return {key: value for key, value in os.environ.items()
            if not key.startswith("GIT_")}


def owns_git_root(path):
    """True when path is its own canonical Git top level.

    A source archive nested under an unrelated repository must
    never inherit that parent's identity or ignore rules.
    """
    try:
        proc = subprocess.run(
            ["git", "-C", path, "rev-parse", "--show-toplevel"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env=git_env())
    except FileNotFoundError:
        return False
    return (proc.returncode == 0 and bool(proc.stdout.strip())
            and os.path.realpath(proc.stdout.strip())
            == os.path.realpath(path))


def tracked_files():
    proc = subprocess.run(
        ["git", "ls-files", "-c", "-o", "--exclude-standard", "-z"],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=git_env())
    if proc.returncode != 0:
        print("FAIL provenance: git ls-files failed")
        sys.exit(1)
    return [rel for rel in
            proc.stdout.decode("utf-8", "surrogateescape").split("\0")
            if rel]


def archive_files():
    """Complete file set from the explicit tree inventory."""
    try:
        inventory = source_inventory.take_tree_inventory(ROOT)
    except OSError as exc:
        print("FAIL provenance: tree inventory failed: %s" % exc)
        sys.exit(1)
    return sorted(entry["path"]
                  for entry in inventory.get("files", [])
                  if entry.get("kind") in ("file", "symlink"))


def enumerated_files():
    """(files, mode): Git only for an owning checkout."""
    if owns_git_root(ROOT):
        return tracked_files(), "git"
    return archive_files(), "archive"


def is_code(rel):
    parts = rel.split("/")
    if any(part in SKIP_DIRS for part in parts[:-1]):
        return False
    # Generated expected outputs: byte-compared against binary
    # stdout by the reports suite, so a header would break them.
    # They inherit the repository default license (LICENSE).
    if parts[0] == "tests" and len(parts) > 1 and parts[1] == "golden":
        return False
    base = parts[-1]
    if rel == "pixi.toml" or parts[0] == "tools":
        return True
    if base in CODE_BASENAMES or base.startswith("Dockerfile"):
        return True
    return base.endswith(CODE_SUFFIXES)


def spdx_of(path):
    with open(path, "rb") as handle:
        head = handle.read(4096).decode("utf-8", "replace")
    match = re.search(r"SPDX-License-Identifier:\s*(\S+)", head)
    return match.group(1) if match else None


def main(argv):
    if argv and argv != ["--list-files"]:
        print("usage: test_provenance.py [--list-files]",
              file=sys.stderr)
        return 2
    files, mode = enumerated_files()
    if argv == ["--list-files"]:
        for rel in sorted(files):
            print(rel)
        return 0
    print("provenance: inventory mode %s (%d files)"
          % (mode, len(files)))
    check("file-inventory-nonempty", len(files) > 100,
          "got %d" % len(files))
    present = set(files)
    omitted = [rel for rel in STATIC_INPUTS if rel not in present]
    check("inventory-required-present", not omitted,
          "; ".join(omitted[:5]))

    offenders = []
    seen_ids = set()
    for rel in sorted(files):
        if not is_code(rel):
            continue
        found = spdx_of(os.path.join(ROOT, rel))
        if found is None:
            offenders.append(rel + " (missing)")
        elif found not in KNOWN_IDS:
            offenders.append(rel + " (unknown id %s)" % found)
        else:
            seen_ids.add(found)
    check("spdx-coverage", not offenders, "; ".join(offenders[:5]))

    for ident in sorted(seen_ids):
        staged = os.path.join(ROOT, KNOWN_IDS[ident])
        check("license-text-%s" % ident, os.path.isfile(staged), staged)
    check("license-default", os.path.isfile(os.path.join(ROOT, "LICENSE")))

    lock_path = os.path.join(ROOT, "toolchain.lock.json")
    with open(lock_path) as handle:
        lock = json.load(handle)
    check("lock-version", lock.get("lock_version") == "1.0.0")
    pin = lock["dependencies"]["libbpf-mojo"]
    check("lock-pin-fields",
          pin.get("status") == "pinned"
          and pin.get("version") and pin.get("source_commit")
          and HEX64.match(pin.get("tarball_sha256", "")),
          json.dumps(pin, sort_keys=True)[:160])
    dumped = json.dumps(lock).lower()
    check("lock-no-unknown",
          "unknown" not in dumped and "tbd" not in dumped)

    notices_path = os.path.join(ROOT, "THIRD-PARTY-NOTICES.md")
    check("notices-present", os.path.isfile(notices_path))
    with open(notices_path) as handle:
        notices = handle.read()
    check("notices-pin",
          pin["version"] in notices
          and pin["source_commit"] in notices)
    lowered = notices.lower()
    check("notices-no-placeholders",
          "todo" not in lowered and "tbd" not in lowered
          and "xxx" not in lowered)

    with open(os.path.join(ROOT, "pixi.toml")) as handle:
        pixi = handle.read()
    mver = re.search(r'^version\s*=\s*"([^"]+)"', pixi, re.M)
    mmojo = re.search(r'^mojo\s*=\s*"==([^"]+)"', pixi, re.M)
    check("pixi-manifest", bool(mver) and bool(mmojo))
    product_version = mver.group(1)
    check("lock-mojo-agrees-pixi",
          lock["toolchain"]["mojo"]["version"] == mmojo.group(1))
    check("pixi-license-declared", 'license = "GPL-3.0-or-later"' in pixi)

    schema_version = lock["product_contracts"]["schema_version"]
    event_version = lock["product_contracts"].get(
        "event_schema_version", schema_version)
    profile_version = lock["product_contracts"].get(
        "profile_schema_version", schema_version)
    doctor_version = lock["product_contracts"].get(
        "doctor_schema_version", schema_version)
    report_version = lock["product_contracts"].get(
        "report_schema_version", schema_version)
    receipt_version = lock["product_contracts"].get(
        "receipt_schema_version", schema_version)
    import glob
    schemas = sorted(glob.glob(os.path.join(ROOT, "schemas", "*.json")))
    check("schemas-present", len(schemas) >= 4, str(len(schemas)))
    bad = []
    for p in schemas:
        base = os.path.basename(p)
        if base.startswith("event-v"):
            want = event_version
        elif base.startswith("profile-v"):
            want = profile_version
        elif base.startswith("doctor-v"):
            want = doctor_version
        elif base.startswith("report-v"):
            want = report_version
        elif base.startswith("receipt-v"):
            want = receipt_version
        else:
            want = schema_version
        if "-v%s.schema.json" % want not in p:
            bad.append(base)
    check("schemas-versioned", not bad, "; ".join(bad[:5]))
    check("versions-distinct-note",
          any("independent" in d
              for d in lock.get("decisions", [])))

    binary = os.path.join(ROOT, "build", "memveil")
    if os.path.isfile(binary):
        proc = subprocess.run([binary, "version"],
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True)
        engine = proc.stdout.strip()
        check("engine-version-matches-pixi",
              proc.returncode == 0
              and engine == "memveil-" + product_version, engine)
    else:
        print("ok engine-version-matches-pixi (no built binary; skipped)")

    missing = [rel for rel in STATIC_INPUTS
               if not os.path.isfile(os.path.join(ROOT, rel))]
    check("package-static-inputs", not missing, "; ".join(missing))
    with open(os.path.join(ROOT, "profiles", "manifest.txt")) as handle:
        listed = [line.strip() for line in handle if line.strip()]
    check("profiles-manifest-nonempty", len(listed) >= 1)
    for name in listed:
        path = os.path.join(ROOT, "profiles", name)
        check("profile-%s" % name, os.path.isfile(path))
        with open(path) as handle:
            json.load(handle)

    print("provenance: all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
