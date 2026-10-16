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
time, not here. Each schema family ships its current contract
plus any retained (superseded but still shipped) versions
pinned in the lock. Exits nonzero on the first failure.
Standard library only. `test_provenance.py --selftest`
exercises the schema-file rule.

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

import glob
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
    "examples/lifecycle-copy/events.ndjson",
    "examples/lifecycle-copy/session.json",
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


VENDOR_TOKEN = "unknown-linux-musl"


def redacted_lock_text(lock):
    """Lock JSON with exactly the validated vendor token exempted.

    The pixi release pin names the upstream musl asset, whose
    target triple legitimately contains "unknown" as the vendor
    field. Only that token occurrence inside each release field
    is removed before placeholder scanning, so placeholder text
    hiding anywhere else in those fields still fails the gate.
    """
    redacted = json.dumps(lock)
    for key in ("release_url", "release_asset"):
        field = lock["toolchain"]["pixi"].get(key, "")
        if field and VENDOR_TOKEN in field:
            redacted = redacted.replace(
                field, field.replace(VENDOR_TOKEN, "", 1), 1)
    return redacted


# Schema families: filename prefix, current-version lock key,
# retained-versions lock key. The session family uses the bare
# schema_version key. A family without a retained key ships only
# its current contract.
SCHEMA_FAMILIES = (
    ("event-v", "event_schema_version", "event_retained_versions"),
    ("profile-v", "profile_schema_version",
     "profile_retained_versions"),
    ("doctor-v", "doctor_schema_version",
     "doctor_retained_versions"),
    ("report-v", "report_schema_version",
     "report_retained_versions"),
    ("receipt-v", "receipt_schema_version",
     "receipt_retained_versions"),
    ("session-v", "schema_version", "schema_retained_versions"),
)


def schema_file_status(basenames, contracts):
    """(bad, missing, inconsistent) for schema files against the lock.

    bad: files matching no pinned (current or retained) version
    for their own family, including unknown families.
    missing: pinned current or retained versions with no file.
    inconsistent: retained pins that are malformed or repeat an
    already pinned version.
    """
    current = contracts["schema_version"]
    present = set(basenames)
    bad = []
    missing = []
    inconsistent = []
    pinned_by_prefix = {}
    for prefix, cur_key, ret_key in SCHEMA_FAMILIES:
        pinned = {"%s" % contracts.get(cur_key, current)}
        raw = contracts.get(ret_key, [])
        if not isinstance(raw, list):
            inconsistent.append("%s: not a list" % ret_key)
            raw = []
        for entry in raw:
            if not isinstance(entry, str) or not entry:
                inconsistent.append(
                    "%s: %r not a version" % (ret_key, entry))
            elif entry in pinned:
                inconsistent.append(
                    "%s: %s repeats a pin" % (ret_key, entry))
            else:
                pinned.add(entry)
        pinned_by_prefix[prefix] = pinned
        for version in sorted(pinned):
            name = "%s%s.schema.json" % (prefix, version)
            if name not in present:
                missing.append(name)
    for base in basenames:
        match = None
        for prefix in pinned_by_prefix:
            if base.startswith(prefix):
                match = prefix
                break
        if match is None:
            bad.append(base)
        elif (not base.endswith(".schema.json")
              or base[len(match):-len(".schema.json")]
              not in pinned_by_prefix[match]):
            bad.append(base)
    return sorted(bad), sorted(missing), sorted(inconsistent)


def run_selftest():
    """Exercise the schema-file rule against the real lock and tree."""
    with open(os.path.join(ROOT, "toolchain.lock.json")) as handle:
        contracts = json.load(handle)["product_contracts"]
    real = sorted(os.path.basename(path) for path in glob.glob(
        os.path.join(ROOT, "schemas", "*.json")))
    results = []

    def check(label, cond, detail=""):
        results.append((bool(cond), "%s%s" % (
            label, (": %s" % detail) if detail and not cond else "")))

    bad, missing, inconsistent = schema_file_status(real, contracts)
    check("known-set-passes",
          not bad and not missing and not inconsistent,
          "; ".join(bad + missing + inconsistent))
    bad, _, _ = schema_file_status(
        real + ["session-v9.9.9.schema.json"], contracts)
    check("stray-unpinned-fails", bad == ["session-v9.9.9.schema.json"],
          "; ".join(bad))
    bad, _, _ = schema_file_status(
        real + ["event-v0.1.0.schema.json"], contracts)
    check("unpinned-version-other-family-fails",
          bad == ["event-v0.1.0.schema.json"], "; ".join(bad))
    bad, _, _ = schema_file_status(
        real + ["audit-v0.1.1.schema.json"], contracts)
    check("unknown-family-fails", bad == ["audit-v0.1.1.schema.json"],
          "; ".join(bad))
    dropped = "session-v%s.schema.json" % contracts["schema_version"]
    _, missing, _ = schema_file_status(
        [base for base in real if base != dropped], contracts)
    check("missing-current-fails", missing == [dropped],
          "; ".join(missing))
    retained = contracts["schema_retained_versions"]
    check("lock-has-retained-fixture", bool(retained), repr(retained))
    if retained:
        dropped = "session-v%s.schema.json" % retained[0]
        _, missing, _ = schema_file_status(
            [base for base in real if base != dropped], contracts)
        check("missing-retained-fails", missing == [dropped],
              "; ".join(missing))
    repeat = dict(contracts)
    repeat["schema_retained_versions"] = [contracts["schema_version"]]
    _, _, inconsistent = schema_file_status(real, repeat)
    check("retained-repeats-current-fails", len(inconsistent) == 1,
          "; ".join(inconsistent))
    malformed = dict(contracts)
    malformed["report_retained_versions"] = "0.1.0"
    _, _, inconsistent = schema_file_status(real, malformed)
    check("retained-malformed-fails", len(inconsistent) == 1,
          "; ".join(inconsistent))
    with open(os.path.join(ROOT, "toolchain.lock.json")) as handle:
        full_lock = json.load(handle)
    redacted = redacted_lock_text(full_lock).lower()
    check("placeholder-real-lock-clean",
          "unknown" not in redacted and "tbd" not in redacted,
          redacted[:200])
    tampered = json.loads(json.dumps(full_lock))
    tampered_asset = "pixi-TBD-unknown-linux-musl.tar.gz"
    tampered["toolchain"]["pixi"]["release_asset"] = tampered_asset
    tampered["toolchain"]["pixi"]["release_url"] = \
        "https://github.com/prefix-dev/pixi/releases/download/v%s/%s" \
        % (tampered["toolchain"]["pixi"]["version"], tampered_asset)
    redacted = redacted_lock_text(tampered).lower()
    check("placeholder-tampered-asset-detected",
          "tbd" in redacted, redacted[:200])
    return results


def main(argv):
    if argv and argv not in (["--list-files"], ["--selftest"]):
        print("usage: test_provenance.py [--list-files|--selftest]",
              file=sys.stderr)
        return 2
    if argv == ["--selftest"]:
        results = run_selftest()
        failed = 0
        for passed, message in results:
            print(("ok " if passed else "FAIL ") + message)
            if not passed:
                failed += 1
        print("provenance-selftest: %d passed, %d failed, %d total"
              % (len(results) - failed, failed, len(results)))
        return 1 if failed else 0
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
    # The pixi release pin names the upstream x86-64 musl asset,
    # whose target triple legitimately contains "unknown" as the
    # vendor field; only that validated token is exempted before
    # scanning for placeholder text, so placeholders hiding
    # elsewhere in the release fields still fail the gate.
    dumped = redacted_lock_text(lock).lower()
    check("lock-no-unknown",
          "unknown" not in dumped and "tbd" not in dumped)

    pixi_pin = lock["toolchain"]["pixi"]
    pixi_asset_ok = (
        pixi_pin.get("release_asset", "").startswith("pixi-")
        and pixi_pin.get("release_asset", "").endswith(".tar.gz"))
    pixi_url_ok = (pixi_pin.get("release_url")
                   == "https://github.com/prefix-dev/pixi/releases/"
                   "download/v%s/%s"
                   % (pixi_pin.get("version", ""),
                      pixi_pin.get("release_asset", "")))
    check("lock-pixi-release-pin",
          bool(pixi_pin.get("version"))
          and pixi_asset_ok and pixi_url_ok
          and HEX64.match(pixi_pin.get("release_sha256", "")),
          json.dumps(pixi_pin, sort_keys=True)[:160])

    workflows = sorted(glob.glob(os.path.join(
        ROOT, ".github", "workflows", "*.yml")))
    check("ci-workflows-present", len(workflows) >= 1,
          "found %d" % len(workflows))
    uses_pattern = re.compile(
        r"^\s*(?:-\s*)?uses:\s*(\S+)(?:\s+#\s*(.*?))?\s*$")
    ref_pattern = re.compile(r"^[\w.-]+/[\w.-]+@[0-9a-f]{40}$")
    tag_pattern = re.compile(r"^v\d+\.\d+\.\d+$")
    for path in workflows:
        base = os.path.basename(path)
        with open(path) as handle:
            text = handle.read()
        refs = []
        for lineno, line in enumerate(text.splitlines(), 1):
            match = uses_pattern.match(line)
            if match:
                refs.append((lineno, match.group(1),
                             (match.group(2) or "").strip()))
        check("ci-actions-pinned-%s" % base,
              len(refs) >= 1
              and all(ref_pattern.match(ref) for _, ref, _ in refs)
              and all(tag_pattern.match(tag) for _, _, tag in refs),
              "; ".join("line %d: %s%s" % (lineno, ref,
                                           " #%s" % tag if tag else "")
                        for lineno, ref, tag in refs)[:200])
        piped_shell = re.search(r"\|\s*(bash|sh)(\s|$|;|&)", text)
        check("ci-no-piped-installers-%s" % base,
              not piped_shell
              and "pixi.sh/install.sh" not in text,
              piped_shell.group(0).strip() if piped_shell else "")
        check("ci-pixi-bootstrap-%s" % base,
              "tools/install-pixi" in text)
        runners = re.findall(r"^\s*runs-on:\s*(.+?)\s*$",
                             text, re.M)
        check("ci-runners-known-%s" % base,
              len(runners) >= 1
              and all(run in ("ubuntu-26.04",
                              "[self-hosted, Linux, X64]")
                             for run in runners),
              "; ".join(runners)[:120])

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

    contracts = lock["product_contracts"]
    schemas = sorted(glob.glob(os.path.join(ROOT, "schemas", "*.json")))
    check("schemas-present", len(schemas) >= 4, str(len(schemas)))
    bad, missing, inconsistent = schema_file_status(
        [os.path.basename(path) for path in schemas], contracts)
    check("schemas-versioned", not bad, "; ".join(bad[:5]))
    check("schemas-pinned-present", not missing, "; ".join(missing[:5]))
    check("schemas-retained-consistent", not inconsistent,
          "; ".join(inconsistent[:5]))
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
