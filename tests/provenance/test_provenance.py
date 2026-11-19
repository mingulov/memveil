#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Provenance gate: licenses, pins, versions, and packager inputs.

Every first-party source file carries an SPDX identifier from a
known set with its license text staged; Cargo pins the exact
toolchain and dependency closure; the engine, spec, and
toolchain versions agree; and every static input the Rust
build and packagers need from this tree exists. Each schema
family ships its current contract plus any retained
(superseded but still shipped) versions pinned below. Exits
nonzero on the first failure. Standard library only.
`test_provenance.py --selftest` exercises the schema-file rule.

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
import hashlib
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
    ".rs", ".c", ".h", ".py", ".sh", ".md", ".yml", ".yaml",
)
CODE_BASENAMES = ("Makefile", "CMakeLists.txt", "Dockerfile")
SKIP_DIRS = ("build", "dist", "target", ".pixi", "__pycache__",
             ".pytest_cache", ".git", ".mypy_cache")

HEX64 = re.compile(r"^[0-9a-f]{64}$")

STATIC_INPUTS = [
    "LICENSE",
    "LICENSES/GPL-2.0.txt",
    "LICENSES/GPL-2.0-only.txt", "LICENSES/GPL-2.0-or-later.txt",
    "docs/quickstart.md", "docs/support.md", "docs/privacy.md",
    "examples/real-capture/events.ndjson",
    "examples/real-capture/session.json",
    "examples/lifecycle-copy/events.ndjson",
    "examples/lifecycle-copy/session.json",
    "profiles/manifest.txt",
    "rust/Cargo.toml", "rust/Cargo.lock",
    "rust/deny.toml",
    "rust/build.rs", "rust/src/lib.rs", "rust/src/main.rs",
    "rust/crates/ebpf/Cargo.toml", "rust/crates/ebpf/Cargo.lock",
    "rust/crates/ebpf/rust-toolchain.toml",
    "rust/crates/ebpf/deny.toml",
    "rust/crates/ebpf-common/Cargo.toml",
    "rust/packaging/deb/control.in",
    "rust/packaging/deb/copyright",
    "rust/packaging/deb/lintian-overrides",
    "rust/packaging/rpm/memveil.spec",
    "rust/packaging/libgcc/PROVENANCE.txt",
    "rust/packaging/libgcc/libgcc-s1_14.2.0-19_amd64.deb",
    "rust/packaging/libgcc/GPL-3.txt",
    "rust/packaging/RUNTIME.LIBRARY.EXCEPTION",
    "rust-toolchain.toml", "mise.toml",
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
    if parts[0] == "tools":
        return True
    if base in CODE_BASENAMES or base.startswith("Dockerfile"):
        return True
    return base.endswith(CODE_SUFFIXES)


def spdx_of(path):
    with open(path, "rb") as handle:
        head = handle.read(4096).decode("utf-8", "replace")
    match = re.search(r"SPDX-License-Identifier:\s*([^\n]+)", head)
    if not match:
        return None
    found = match.group(1).strip()
    for tail in ("*/", "-->"):
        if found.endswith(tail):
            found = found[:-len(tail)].strip()
    return found


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

# Shipped schema pins (cutover: carried verbatim from the retired
# toolchain lock's product contracts; product, schema, and
# toolchain versions stay independent by policy, not by format).
SCHEMA_CONTRACTS = {
    "schema_version": "0.1.4",
    "event_schema_version": "0.1.2",
    "event_retained_versions": ["0.1.1"],
    "profile_schema_version": "0.1.2",
    "profile_retained_versions": ["0.1.1"],
    "doctor_schema_version": "0.1.1",
    "doctor_retained_versions": ["0.1.0"],
    "report_schema_version": "0.1.4",
    "report_retained_versions": ["0.1.3", "0.1.2", "0.1.1", "0.1.0"],
    "receipt_schema_version": "0.1.0",
    "schema_retained_versions": ["0.1.3", "0.1.2", "0.1.1"],
}


def schema_file_status(basenames, contracts):
    """(bad, missing, inconsistent) for schema files against the pins.

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
    """Exercise the schema-file rule against the pins and tree."""
    contracts = SCHEMA_CONTRACTS
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
    check("pins-have-retained-fixture", bool(retained), repr(retained))
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
    return results


def _cargo_version(text):
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
    return match.group(1) if match else ""


def _toolchain_channel(text):
    match = re.search(r'^channel\s*=\s*"([^"]+)"', text, re.M)
    return match.group(1) if match else ""


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

    with open(os.path.join(ROOT, "rust", "Cargo.toml")) as handle:
        product_version = _cargo_version(handle.read())
    check("cargo-version", bool(product_version), product_version)
    with open(os.path.join(ROOT, "rust-toolchain.toml")) as handle:
        host_channel = _toolchain_channel(handle.read())
    with open(os.path.join(
            ROOT, "rust", "crates", "ebpf", "rust-toolchain.toml")) as handle:
        ebpf_channel = _toolchain_channel(handle.read())
    check("toolchain-pinned", bool(host_channel) and bool(ebpf_channel),
          "%s / %s" % (host_channel, ebpf_channel))
    with open(os.path.join(ROOT, "mise.toml")) as handle:
        mise = handle.read()
    mise_rust = re.search(r'^rust\s*=\s*"([^"]+)"', mise, re.M)
    check("toolchain-mise-agrees",
          bool(mise_rust) and mise_rust.group(1) == host_channel,
          mise_rust.group(1) if mise_rust else "no rust pin")
    with open(os.path.join(ROOT, "rust", "build.rs")) as handle:
        build_rs = handle.read()
    bpf_toolchain = re.search(
        r'BPF_TOOLCHAIN[^\n"]*"([^"\n]+)"', build_rs)
    check("toolchain-ebpf-agrees-build",
          bool(bpf_toolchain) and bpf_toolchain.group(1) == ebpf_channel,
          bpf_toolchain.group(1) if bpf_toolchain else "no BPF pin")
    for rel in ("rust/Cargo.lock", "rust/crates/ebpf/Cargo.lock",
                "rust/deny.toml", "rust/crates/ebpf/deny.toml"):
        path = os.path.join(ROOT, rel)
        check("pinfile-" + rel.replace("/", "-"),
              os.path.isfile(path) and os.path.getsize(path) > 0, rel)

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
    lowered = notices.lower()
    check("notices-no-placeholders",
          "todo" not in lowered and "tbd" not in lowered
          and "xxx" not in lowered)

    contracts = SCHEMA_CONTRACTS
    schemas = sorted(glob.glob(os.path.join(ROOT, "schemas", "*.json")))
    check("schemas-present", len(schemas) >= 4, str(len(schemas)))
    bad, missing, inconsistent = schema_file_status(
        [os.path.basename(path) for path in schemas], contracts)
    check("schemas-versioned", not bad, "; ".join(bad[:5]))
    check("schemas-pinned-present", not missing, "; ".join(missing[:5]))
    check("schemas-retained-consistent", not inconsistent,
          "; ".join(inconsistent[:5]))

    binary = os.path.join(ROOT, "build", "memveil")
    if os.path.isfile(binary):
        proc = subprocess.run([binary, "version"],
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True)
        engine = proc.stdout.strip()
        check("engine-version-matches-cargo",
              proc.returncode == 0
              and engine == "memveil-" + product_version, engine)
    else:
        print("ok engine-version-matches-cargo (no built binary; skipped)")

    with open(os.path.join(ROOT, "rust", "packaging", "rpm",
                           "memveil.spec")) as handle:
        spec = handle.read()
    mspec = re.search(r"^Version:\s*(\S+)", spec, re.M)
    check("spec-version-matches-cargo",
          bool(mspec) and mspec.group(1) == product_version,
          mspec.group(1) if mspec else "no Version line")

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
