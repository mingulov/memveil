#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Seal local release outputs into an immutable candidate manifest.

The primary release path builds clean source commit C locally once
and retains six artifacts: the owner bundle tarball, the .deb, the
.rpm, a source archive of C, an SPDX SBOM over the payload closure,
and a local-build provenance record embedding the build receipt.
`tools/candidate seal` verifies every artifact against C and the
presented bundle directory, then writes one `memveil-candidate/2`
manifest whose content digest is the candidate ID.

Each binding is checked independently: the bundle MANIFEST.json
revision claim alone never suffices. The source archive must equal
the git tree at C byte for byte, the build receipt must name C and
the presented engine/BPF bytes, the Cargo lock digests must match
the archived locks, the probed build tools must match the bundle
record and the source pin, and the full copied-file closure
collected from the three archives must equal the sealed files map.
Anything stale, tampered, or /1 fails closed with ValueError.

The packager records the build receipt in the bundle MANIFEST.json
when the engine is built: source C, tree inventory, tool versions,
the engine/BPF output digests, and the build-time worktree
cleanliness. `tools/candidate provenance`
composes the local-build provenance record from that recorded
receipt plus the re-hashed artifact subjects, never inventing
values. The seal requires the provenance receipt to equal the
recorded receipt, cross-checks the recorded bpf-linker against
the probed toolchain, and requires the receipt to record an
in-flow candidate-mode build, so a prebuilt engine repackaged at
C with a fresh receipt, or one swapped after the receipt was
recorded, fails closed.

Qualification rederives every required signed gate over retained
evidence without rebuilding: each gate receipt is verified against
pinned trust, non-matrix measurements are re-read from retained
sources and their predicates rederived, and the matrix gate binds
every consumed evidence file through a signed noncircular inventory
digest that is verified before its signature is trusted. An
evidence-only commit Q carries the qualification and tested
payload; anything stale, tampered, unsigned, or /1 fails closed
with ValueError.

Usage:
  tools/candidate seal --bundle-dir D --artifacts-dir A --policy P \\
      --out M [--source-root R] [--harness-bin H]
  tools/candidate provenance --bundle-dir D --bundle B --deb E \\
      --rpm R --source S --sbom J --out P [--source-root R]
  tools/candidate qualify --manifest M --qualification Q --policy P \\
      --evidence-dir E [--source-tree S]
  tools/candidate write-gate-receipt --gate G --candidate C \\
      --inputs I --key K --out R
  tools/candidate write-qualification --manifest M --policy P \\
      --gates G... --evidence-dir E --out Q
  tools/candidate write-remote --import I --checks C... --out R
Standard library only. Exit 0 prints the sealed digest; exit 1
reports the reason on stderr.

The authoring commands verify before they write and never
invent values: gate receipts bind retained inputs bytes under
the qualifier key, qualifications assemble only verified
receipt sets that equal the policy and pack the evidence once
so the archived digest binds real bytes, and remote custody
assembles only import-bound check sets whose envelopes agree.
"""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib

SCHEMA = "memveil-candidate/2"
PROVENANCE_SCHEMA = "memveil-local-build/2"
MATRIX_INPUT_SCHEMA = "memveil-matrix-input/2"
QUALIFICATION_SCHEMA = "memveil-qualification/1"
GATE_RECEIPT_SCHEMA = "memveil-gate-receipt/1"
GATE_INPUT_SCHEMA = "memveil-gate-input/1"
POLICY_SCHEMA = "memveil-candidate-policy/1"
IMPORT_SCHEMA = "memveil-candidate-import/1"
REMOTE_CUSTODY_SCHEMA = "memveil-remote-custody/1"
REMOTE_GATE_SCHEMA = "memveil-remote-gate/1"
CHECK_FILE_SCHEMA = "memveil-remote-check/1"
MATRIX_GATE = "kernel-matrix/2"
LIVE_GATE = "live-campaign/1"
LIVE_CAMPAIGNS = ("overhead", "soak")
LIVE_TOTALS = ("legs", "failed_legs", "target_failures",
               "cleanup_mismatches")
GATE_ID_RE = r"[a-z][a-z0-9-]*/[1-9][0-9]*"
# Required remote checks with their count measurement. Mirrors
# candidate_custody.REMOTE_CHECKS exactly; the mirror is pinned
# by test_remote_checks_mirror_custody, since this module cannot
# import the custody layer without inverting the dependency.
REMOTE_CHECKS = {"tampered-payload/1": "refusals",
                 "promotion-dry-run/1": "verified_files",
                 "independent-attestation/1":
                 "verified_subjects",
                 "required-checks/1": "enforced_checks",
                 "no-overwrite/1": "preserved_assets"}
SIGNING_NAMESPACE = "memveil-candidate"
EVIDENCE_TESTED = "packaging/tested-payload.sha256"
EVIDENCE_QUALIFICATIONS = "packaging/qualifications/"
ORIGIN = "local-build"
ROLES = frozenset({"bundle", "deb", "rpm", "source", "sbom", "provenance"})
BPF_OBJECTS = ("swiotlb_attempt.bpf.o", "swiotlb_lifecycle.bpf.o",
               "swiotlb_copy.bpf.o")
DOCUMENT_LIMIT = 16 * 1024 * 1024
HARNESS_PACKAGE = "memveil-release-entry"
# Matrix-runner top-level outputs the signed evidence
# inventory authenticates when present: the campaign
# provenance record (harness.json: tool versions, run ID,
# source digest, harness commit) and the rendered verdict
# log (summary.txt: the same merged verdicts as
# summary.json in operator-readable form). Row verdict
# sidecars and summary.json keep their own rules below;
# the raw boot command line stays local-only and is never
# admitted here.
MATRIX_RUNNER_FILES = frozenset({"harness.json", "summary.txt"})


def require(condition, message):
    if not condition:
        raise ValueError(message)


def exact(value, keys, label):
    require(isinstance(value, dict) and set(value) == set(keys),
            label + " has invalid fields")


def hexid(value, width=64):
    require(isinstance(value, str)
            and re.fullmatch("[0-9a-f]{%d}" % width, value)
            and value != "0" * width, "invalid or placeholder identity")
    return value


def relative(value):
    require(isinstance(value, str) and value and "\\" not in value
            and all(part not in ("", ".", "..")
                    for part in value.split("/"))
            and not any(ord(char) < 33 or ord(char) > 126
                        for char in value), "invalid relative path")
    return value


def version(value):
    require(isinstance(value, str)
            and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+"
                             r"(?:[-+][0-9A-Za-z.+-]+)?", value)
            and len(value) <= 64, "invalid tool version")
    return value


def parse_size(value):
    require(isinstance(value, str) and len(value) <= 20
            and re.fullmatch(r"0|[1-9][0-9]*", value),
            "size must be a canonical unsigned decimal string")
    size = int(value)
    require(size <= 18446744073709551615,
            "size exceeds unsigned 64-bit range")
    return size


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True) + "\n").encode()


def digest_bytes(value):
    return hashlib.sha256(value).hexdigest()


def digest_canonical(obj):
    """SHA-256 hex of the canonical JSON encoding of obj."""
    return digest_bytes(canonical(obj))


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key: " + key)
        result[key] = value
    return result


def read_regular(path, limit=DOCUMENT_LIMIT):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= limit,
                "invalid or oversized regular file")
        value = stream.read(limit + 1)
    require(len(value) <= limit, "oversized document")
    return value


def _parse_json(data):
    """Strict-parse document bytes; duplicate keys fail closed."""
    try:
        value = json.loads(
            data, object_pairs_hook=unique,
            parse_constant=lambda x: (_ for _ in ()).throw(
                ValueError(x)))
    except (RecursionError, UnicodeError) as error:
        raise ValueError("invalid JSON document") from error

    def depth(item, level=0):
        require(level <= 64, "document nesting exceeds limit")
        if isinstance(item, dict):
            for child in item.values():
                depth(child, level + 1)
        elif isinstance(item, list):
            for child in item:
                depth(child, level + 1)
    depth(value)
    return value


def read_json(path, sealed=False):
    data = read_regular(path)
    value = _parse_json(data)
    if sealed:
        require(data == canonical(value),
                "document bytes are not canonical")
    return value


def digest(path):
    found = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1048576), b""):
            found.update(chunk)
    return found.hexdigest()


def write_once(path, data):
    """Write bytes to a new file; refuse to overwrite (FileExistsError)."""
    with open(path, "xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def has_runtime_so(files):
    """True when files{} carries a lib/memveil/*.so* member.

    A bare prefix match would let a README satisfy the runtime
    closure requirement; only a direct lib entry whose name
    carries `.so` counts.
    """
    for name in files:
        if not name.startswith("lib/memveil/"):
            continue
        rest = name[len("lib/memveil/"):]
        if rest and "/" not in rest and ".so" in rest:
            return True
    return False


def validate_manifest(doc):
    """Validate a memveil-candidate/2 manifest; return it or ValueError.

    /1 manifests (and any other schema) fail closed here and are
    never evaluated.
    """
    exact(doc, {"schema", "origin", "source", "toolchain",
                "build_receipt_sha256", "bundle_manifest_sha256",
                "policy_sha256", "files", "artifacts"}, "candidate")
    require(doc["schema"] == SCHEMA,
            "unsupported candidate schema %r: /1 inputs fail closed"
            % (doc.get("schema"),))
    require(doc["origin"] == ORIGIN,
            "candidate requires truthful local build origin")
    exact(doc["source"], {"commit", "tree", "inventory_sha256"},
          "source")
    for key in ("commit", "tree"):
        hexid(doc["source"][key], 40)
    hexid(doc["source"]["inventory_sha256"])
    exact(doc["toolchain"],
          {"cargo_lock_sha256", "ebpf_lock_sha256", "tools"},
          "toolchain")
    hexid(doc["toolchain"]["cargo_lock_sha256"])
    hexid(doc["toolchain"]["ebpf_lock_sha256"])
    exact(doc["toolchain"]["tools"], {"cargo", "rustc", "bpf_linker"},
          "toolchain tools")
    for tool in ("cargo", "rustc", "bpf_linker"):
        version(doc["toolchain"]["tools"][tool])
    for key in ("build_receipt_sha256", "bundle_manifest_sha256",
                "policy_sha256"):
        hexid(doc[key])
    require(isinstance(doc["files"], dict) and doc["files"],
            "empty full file closure")
    for name, value in doc["files"].items():
        relative(name)
        require(name != "MANIFEST.json", "invalid copied file")
        hexid(value)
        installed_file_path(name)
    require("bin/memveil" in doc["files"],
            "missing required runtime component")
    require(has_runtime_so(doc["files"]),
            "missing required runtime component")
    require({name for name in doc["files"]
             if name.startswith("bpf/")}
            == {"bpf/" + name for name in BPF_OBJECTS},
            "unverified BPF object in the file closure")
    require(any(name.startswith("profiles/")
                for name in doc["files"]),
            "missing required runtime component")
    require(isinstance(doc["artifacts"], list), "invalid artifacts")
    roles, names = [], []
    for entry in doc["artifacts"]:
        exact(entry, {"role", "name", "size", "sha256"}, "artifact")
        require(entry["role"] in ROLES, "unknown artifact role")
        require("/" not in relative(entry["name"]),
                "artifact name must be a basename")
        parse_size(entry["size"])
        hexid(entry["sha256"])
        roles.append(entry["role"])
        names.append(entry["name"])
    require(set(roles) == ROLES and len(roles) == len(ROLES)
            and len(set(names)) == len(names),
            "missing or duplicate artifact")
    return doc


def load_manifest(path, expected_digest=None):
    data = read_regular(path)
    if expected_digest is not None:
        require(digest_bytes(data) == hexid(expected_digest),
                "candidate digest mismatch")
    doc = read_json(path, sealed=True)
    require(data == canonical(doc), "candidate changed during reading")
    return validate_manifest(doc)


def seal_manifest(doc, path):
    validate_manifest(doc)
    data = canonical(doc)
    write_once(path, data)
    return digest_bytes(data)


def artifact(doc, role):
    return next(entry for entry in doc["artifacts"]
                if entry["role"] == role)


def verify_file(path, entry):
    path = Path(path)
    require(not path.is_symlink() and path.is_file(),
            "artifact must be a regular file")
    require(str(path.stat().st_size) == entry["size"]
            and digest(path) == entry["sha256"],
            "artifact size/hash mismatch: " + entry["name"])


def installed_file_path(name):
    """Installed destination of one bundle member in .deb/.rpm.

    Mirrors the deb packager mapping (and the reverse of the rpm
    spec check): binary, closure lib, BPF inspection copies,
    profiles, docs plus worked examples, and every license/notice
    text each have exactly one FHS destination. Anything else
    fails closed.
    """
    if not isinstance(name, str) or not name \
            or name.startswith("/"):
        raise ValueError("invalid bundle file path: %r" % (name,))
    if any(part in ("", ".", "..") for part in name.split("/")):
        raise ValueError("invalid bundle file path: " + name)
    if name.startswith(("docs/", "profiles/")):
        return "usr/share/memveil/" + name
    if name.startswith("examples/"):
        return "usr/share/memveil/docs/" + name
    if name in ("LICENSE", "THIRD-PARTY-NOTICES.md") \
            or name.startswith(("LICENSES/", "licenses/")):
        return "usr/share/doc/memveil/" + name
    if name == "bin/memveil" or name.startswith("lib/memveil/"):
        return "usr/" + name
    if name.startswith("bpf/"):
        return "usr/lib/memveil/" + name[4:]
    raise ValueError("unknown bundle path: " + name)


def expected_payload(manifest):
    """Full copied-file closure: bundle/<f> plus installed deb/rpm."""
    result = {}
    for name, value in manifest["files"].items():
        result["bundle/" + name] = value
        for kind in ("deb", "rpm"):
            result[kind + "/" + installed_file_path(name)] = value
    return result


def git_env():
    return {key: value for key, value in os.environ.items()
            if not key.startswith("GIT_")}


def git(root, *args):
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), *args],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env=git_env())
    except OSError as error:
        raise ValueError("cannot run git: %s" % error) from error
    require(proc.returncode == 0,
            "git %s failed" % " ".join(args[:2]))
    return proc.stdout.strip()


def git_inventory(root, commit):
    """Git-derived source inventory at commit: (entries, digest).

    Entries come from `git ls-tree` plus batched blob reads, so the
    digest is purely commit-derived and immune to worktree strays.
    Files carry path/kind/mode/size/sha256, symlinks path/kind/mode/
    target, directories path/kind/mode, with raw git modes. The
    digest hashes one sorted-keys JSON line per path-sorted entry,
    the same construction as the source inventory digest.
    """
    hexid(commit, 40)
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "ls-tree", "-r", "-t", "-z",
             commit],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=git_env())
    except OSError as error:
        raise ValueError("cannot run git: %s" % error) from error
    require(proc.returncode == 0, "unknown source commit")
    blobs, entries = [], []
    for record in proc.stdout.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw = record.split(b"\t", 1)
            mode, kind, oid = metadata.decode("ascii").split()
            path = raw.decode("utf-8")
        except (ValueError, UnicodeError) as error:
            raise ValueError("invalid git tree entry") from error
        relative(path)
        if kind == "tree":
            require(mode == "040000", "unsupported tree mode")
            entries.append({"path": path, "kind": "dir",
                            "mode": mode})
        elif kind == "blob" and mode in ("100644", "100755"):
            entries.append({"path": path, "kind": "file",
                            "mode": mode, "oid": oid})
            blobs.append(oid)
        elif kind == "blob" and mode == "120000":
            entries.append({"path": path, "kind": "symlink",
                            "mode": mode, "oid": oid})
            blobs.append(oid)
        else:
            raise ValueError(
                "unsupported source archive entry: " + path)
    content = git_batch(root, blobs)
    resolved = []
    for entry in entries:
        oid = entry.pop("oid", None)
        if entry["kind"] == "dir":
            resolved.append(entry)
        elif entry["kind"] == "symlink":
            try:
                target = content[oid].decode("utf-8")
            except UnicodeError as error:
                raise ValueError(
                    "invalid symlink target") from error
            require(target, "empty symlink target")
            entry["target"] = target
            resolved.append(entry)
        else:
            entry["size"] = len(content[oid])
            entry["sha256"] = digest_bytes(content[oid])
            resolved.append(entry)
    resolved.sort(key=lambda entry: entry["path"])
    found = hashlib.sha256()
    for entry in resolved:
        found.update(json.dumps(
            entry, sort_keys=True,
            separators=(",", ":")).encode("utf-8"))
        found.update(b"\n")
    return resolved, found.hexdigest()


def git_batch(root, oids):
    """{oid: bytes} for every oid via one `git cat-file --batch`."""
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "cat-file", "--batch"],
            input=("".join(oid + "\n" for oid in oids)).encode(
                "ascii"),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=git_env())
    except OSError as error:
        raise ValueError("cannot run git: %s" % error) from error
    require(proc.returncode == 0, "cannot read source blobs")
    content, rest = {}, proc.stdout
    for oid in oids:
        try:
            header, rest = rest.split(b"\n", 1)
            found, kind, size = header.decode("ascii").split()
            size = int(size)
            data = rest[:size]
            rest = rest[size:]
            require(rest[:1] == b"\n", "cannot read source blobs")
            rest = rest[1:]
        except (ValueError, IndexError) as error:
            raise ValueError("cannot read source blobs") from error
        require(found == oid and kind == "blob" and len(data) == size,
                "cannot read source blobs")
        content[oid] = data
    return content


def probe_tool_versions(root):
    """Ambient {cargo, rustc, bpf_linker} versions under the repo pin.

    Every invocation strips RUSTUP_TOOLCHAIN and runs in the source
    root so the checkout pin wins over ambient overrides.
    """
    env = {key: value for key, value in os.environ.items()
           if key != "RUSTUP_TOOLCHAIN"}
    found = {}
    for tool, argv in (("cargo", ["cargo", "--version"]),
                      ("rustc", ["rustc", "--version"]),
                      ("bpf_linker", ["bpf-linker", "--version"])):
        try:
            proc = subprocess.run(
                argv, cwd=str(root), stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, env=env)
        except OSError as error:
            raise ValueError(
                "cannot probe %s: %s" % (tool, error)) from error
        require(proc.returncode == 0, "cannot probe " + tool)
        try:
            token = proc.stdout.split()[1]
        except IndexError as error:
            raise ValueError(
                "cannot probe " + tool) from error
        token = token[1:] if token.startswith("v") else token
        try:
            version(token)
        except ValueError as error:
            raise ValueError(
                "cannot probe %s: bad version %r"
                % (tool, token)) from error
        found[tool] = token
    return found


def toolchain_channel(root):
    """`channel` value from the source root rust-toolchain.toml.

    Parsed with the standard TOML reader, so quoted styles,
    trailing comments, and whitespace all resolve exactly as
    the toolchain file means them.
    """
    path = os.path.join(str(root), "rust-toolchain.toml")
    try:
        with open(path, "rb") as handle:
            doc = tomllib.load(handle)
    except OSError as error:
        raise ValueError(
            "source lacks rust-toolchain.toml") from error
    except tomllib.TOMLDecodeError as error:
        raise ValueError(
            "source toolchain pin is invalid") from error
    try:
        channel = doc["toolchain"]["channel"]
    except (KeyError, TypeError) as error:
        raise ValueError(
            "source toolchain pin has no channel") from error
    require(isinstance(channel, str) and channel,
            "source toolchain pin has no channel")
    return channel


def check_toolchain_pin(root, tools):
    """Require the probed cargo/rustc to match the source pin.

    A fully-pinned `channel = "x.y.z"` in rust-toolchain.toml must
    equal both probed versions; anything else (a named channel or
    an unparseable pin) leaves the ambient toolchain to the
    bundle-record cross-checks.
    """
    channel = toolchain_channel(root)
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", channel or ""):
        require(tools["cargo"] == channel
                and tools["rustc"] == channel,
                "build toolchain differs from the source pin")


def verify_bundle_dir(bundle_dir):
    """Verify a bundle directory against its MANIFEST.json.

    Every staged file must match files{} exactly with no extras,
    the BPF inspection copies must equal the engine's embedded
    manifest, the recorded build receipt must name the presented
    engine/BPF bytes, and the runtime members must be present.
    Returns the extracted facts; cross-checks against C happen in
    the seal.
    """
    root = Path(bundle_dir)
    require(root.is_dir() and not root.is_symlink(),
            "bundle directory is missing")
    manifest_path = root / "MANIFEST.json"
    bundled = read_json(manifest_path)
    try:
        files = bundled["files"]
        embedded = bundled["embedded_bpf"]
        revision = bundled["memveil_revision"]
        cargo = bundled["cargo"]
        toolchain = bundled["toolchain"]
    except (KeyError, TypeError) as error:
        raise ValueError(
            "bundle MANIFEST.json lacks required facts") from error
    require(isinstance(files, dict) and files,
            "bundle MANIFEST.json has no files")
    for name, value in files.items():
        relative(name)
        require(name != "MANIFEST.json", "invalid bundle file")
        hexid(value)
    observed = {}
    for current, dirs, names in os.walk(root):
        for leaf in sorted(dirs + names):
            full = os.path.join(current, leaf)
            mode = os.lstat(full).st_mode
            require(stat.S_ISREG(mode) or stat.S_ISDIR(mode),
                    "unsupported bundle entry: " + os.path.relpath(
                        full, root))
        for leaf in sorted(names):
            full = os.path.join(current, leaf)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            observed[rel] = digest(full)
    require(set(observed) == set(files) | {"MANIFEST.json"},
            "bundle files differ from MANIFEST.json")
    for name, value in files.items():
        require(observed[name] == value,
                "bundle file differs from MANIFEST.json: " + name)
    require("bin/memveil" in files, "bundle lacks the engine")
    require(has_runtime_so(files),
            "bundle lacks the runtime closure")
    require({name for name in files if name.startswith("bpf/")}
            == {"bpf/" + name for name in BPF_OBJECTS},
            "bundle lacks the BPF inspection copies")
    require(any(name.startswith("profiles/") for name in files),
            "bundle lacks profiles")
    require(isinstance(embedded, dict)
            and set(embedded) == set(BPF_OBJECTS),
            "bundle lacks the embedded BPF manifest")
    for name in BPF_OBJECTS:
        hexid(embedded[name])
        require(observed["bpf/" + name] == embedded[name],
                "bundle BPF copy differs from the engine's "
                "embedded manifest: bpf/" + name)
    try:
        receipt = bundled["build_receipt"]
    except (KeyError, TypeError) as error:
        raise ValueError(
            "bundle MANIFEST.json lacks a build receipt") from error
    exact(receipt,
          {"source_commit", "inventory_sha256", "tools", "outputs",
           "clean_tree", "built_from_source"},
          "recorded build receipt")
    hexid(receipt["source_commit"], 40)
    hexid(receipt["inventory_sha256"])
    require(receipt["clean_tree"] is True,
            "bundle was built from a dirty worktree")
    require(receipt["built_from_source"] is True,
            "bundle was not built from source in candidate mode")
    exact(receipt["tools"], {"cargo", "rustc", "bpf_linker"},
          "recorded build tools")
    for tool in ("cargo", "rustc", "bpf_linker"):
        version(receipt["tools"][tool])
    outputs = receipt["outputs"]
    exact(outputs, {"engine_sha256", "bpf"}, "recorded build outputs")
    hexid(outputs["engine_sha256"])
    require(isinstance(outputs["bpf"], dict)
            and set(outputs["bpf"]) == set(BPF_OBJECTS),
            "recorded build outputs have invalid BPF names")
    for name in BPF_OBJECTS:
        hexid(outputs["bpf"][name])
    require(outputs["engine_sha256"] == observed.get("bin/memveil"),
            "bundle build receipt engine differs from the staged "
            "files")
    for name in BPF_OBJECTS:
        require(outputs["bpf"][name] == observed.get("bpf/" + name),
                "bundle build receipt BPF differs from the staged "
                "files: bpf/" + name)
    require(isinstance(revision, str) and revision,
            "bundle lacks a source revision")
    try:
        lock_sha = cargo["lock_sha256"]
        ebpf_lock_sha = cargo["ebpf_lock_sha256"]
        cargo_ver = toolchain["cargo"]["version"]
        rustc_ver = toolchain["rustc"]["version"]
    except (KeyError, TypeError) as error:
        raise ValueError(
            "bundle MANIFEST.json lacks toolchain facts") from error
    hexid(lock_sha)
    hexid(ebpf_lock_sha)
    require(isinstance(cargo_ver, str) and cargo_ver
            and isinstance(rustc_ver, str) and rustc_ver,
            "bundle MANIFEST.json lacks tool versions")
    try:
        engine_version = bundled["engine_version"]
    except (KeyError, TypeError) as error:
        raise ValueError(
            "bundle MANIFEST.json lacks an engine version") from error
    version(engine_version)
    manifest_bytes = read_regular(manifest_path)
    return {"files": files, "manifest_bytes": manifest_bytes,
            "manifest_sha256": digest_bytes(manifest_bytes),
            "revision": revision, "engine_version": engine_version,
            "lock_sha256": lock_sha,
            "ebpf_lock_sha256": ebpf_lock_sha,
            "cargo_version": cargo_ver, "rustc_version": rustc_ver,
            "build_receipt": receipt}


def safe_extract(archive, destination, single_root, symlinks):
    """Extract a gzip tar into a newly created directory.

    Refuses absolute or escaping names, duplicates, links and
    special files, and special permission bits. Source archives
    may carry symlinks (recorded, never followed); bundles may
    not. A symlink that is a path prefix of another member is
    refused before anything is extracted, and symlinks are
    created only after all other members, so no write can pass
    through an extracted link. With single_root, require one
    top directory and return it; otherwise return the
    destination itself.
    """
    destination = Path(destination)
    destination.mkdir(mode=0o700)
    try:
        stream = tarfile.open(archive, "r:gz")
    except (tarfile.TarError, OSError) as error:
        raise ValueError(
            "cannot open archive: %s" % error) from error
    with stream:
        try:
            members = stream.getmembers()
        except (tarfile.TarError, OSError) as error:
            raise ValueError(
                "cannot list archive: %s" % error) from error
        names = set()
        links = set()
        require(members and len(members) <= 100000,
                "invalid archive member count")
        total = 0
        for entry in members:
            name = relative(entry.name.rstrip("/")
                            if entry.isdir() else entry.name)
            require(name not in names, "duplicate archive member")
            allowed = entry.isfile() or entry.isdir() \
                or (symlinks and entry.issym())
            require(allowed,
                    "archive links and special files are forbidden")
            require(not entry.mode & 0o7000,
                    "archive special permission bits forbidden")
            names.add(name)
            if entry.issym():
                links.add(name)
            total += entry.size
            require(total <= 8 * 1024 ** 3,
                    "archive exceeds extraction limit")
        if single_root:
            tops = {name.split("/")[0] for name in names}
            require(len(tops) == 1
                    and any("/" in name for name in names),
                    "archive requires one root")
        parents = set()
        for name in names:
            parts = name.split("/")
            for cut in range(1, len(parts)):
                parents.add("/".join(parts[:cut]))
        clash = sorted(links & parents)
        require(not clash,
                "archive member escapes through a symlink: "
                + (clash[0] if clash else ""))
        ordered = sorted(members, key=lambda entry: entry.issym())
        for entry in ordered:
            path = destination / entry.name
            if entry.isdir():
                path.mkdir(parents=True, exist_ok=True)
            elif entry.issym():
                path.parent.mkdir(parents=True, exist_ok=True)
                try:
                    os.symlink(entry.linkname, path)
                except OSError as error:
                    raise ValueError(
                        "cannot extract archive link") from error
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                try:
                    source = stream.extractfile(entry)
                    require(source is not None,
                            "cannot extract archive member")
                    with source, open(path, "xb") as target:
                        shutil.copyfileobj(source, target)
                except (tarfile.TarError, OSError) as error:
                    raise ValueError(
                        "cannot extract archive member") from error
                path.chmod(entry.mode & 0o777)
    if single_root:
        return destination / next(iter(tops))
    return destination


def discover_artifacts(directory, manifest_bytes):
    """Map the six staged artifacts to roles by name and content.

    The directory must hold exactly one .deb, one .rpm, two
    .tar.gz files, one .spdx.json, and one other .json file. The
    bundle tarball is the archive whose top MANIFEST.json bytes
    equal the verified bundle manifest; the other tarball is the
    source archive.
    """
    directory = Path(directory)
    require(directory.is_dir() and not directory.is_symlink(),
            "artifacts directory is missing")
    leaves = sorted(os.listdir(directory))
    require(leaves, "artifacts directory is empty")
    for leaf in leaves:
        full = directory / leaf
        require(not full.is_symlink() and full.is_file(),
                "artifact must be a regular file: " + leaf)
    deb = [leaf for leaf in leaves if leaf.endswith(".deb")]
    rpm = [leaf for leaf in leaves if leaf.endswith(".rpm")]
    tars = [leaf for leaf in leaves if leaf.endswith(".tar.gz")]
    spdx = [leaf for leaf in leaves if leaf.endswith(".spdx.json")]
    rest = [leaf for leaf in leaves
            if leaf not in deb + rpm + tars + spdx]
    require(len(deb) == 1, "want exactly one .deb artifact")
    require(len(rpm) == 1, "want exactly one .rpm artifact")
    require(len(tars) == 2, "want exactly two .tar.gz artifacts")
    require(len(spdx) == 1, "want exactly one SBOM artifact")
    require(len(rest) == 1 and rest[0].endswith(".json"),
            "want exactly one provenance artifact")
    bundle_leaf, source_leaf = None, None
    for leaf in tars:
        if bundle_tarball_matches(directory / leaf, manifest_bytes):
            require(bundle_leaf is None,
                    "two bundle tarballs presented")
            bundle_leaf = leaf
        else:
            require(source_leaf is None,
                    "two source archives presented")
            source_leaf = leaf
    require(bundle_leaf is not None,
            "no bundle tarball matches the bundle directory")
    return {"bundle": directory / bundle_leaf,
            "deb": directory / deb[0], "rpm": directory / rpm[0],
            "source": directory / source_leaf,
            "sbom": directory / spdx[0],
            "provenance": directory / rest[0]}


def bundle_tarball_matches(path, manifest_bytes):
    """True when the tarball holds the verified MANIFEST.json bytes."""
    try:
        stream = tarfile.open(path, "r:gz")
    except (tarfile.TarError, OSError):
        return False
    with stream:
        try:
            members = stream.getmembers()
        except (tarfile.TarError, OSError):
            return False
        tops = {entry.name.split("/")[0] for entry in members
                if "/" in entry.name}
        if len(tops) != 1:
            return False
        top = next(iter(tops))
        try:
            member = stream.getmember(top + "/MANIFEST.json")
            source = stream.extractfile(member)
            if source is None:
                return False
            data = source.read(DOCUMENT_LIMIT + 1)
        except (KeyError, tarfile.TarError, OSError):
            return False
    return data == manifest_bytes


def walk_files(root):
    """({rel: sha256}, {rel: target}, {dirs}, {rel: exec}) walk.

    The fourth map records the owner-execute bit per regular
    file, so archive verifiers can bind executable bits to
    their pinned source instead of trusting tar modes.
    """
    files, links, dirs, execs = {}, {}, set(), {}
    for current, subdirs, names in os.walk(root):
        for leaf in sorted(subdirs + names):
            full = os.path.join(current, leaf)
            mode = os.lstat(full).st_mode
            require(stat.S_ISREG(mode) or stat.S_ISDIR(mode)
                    or stat.S_ISLNK(mode),
                    "unsupported archive entry: " + os.path.relpath(
                        full, root))
        for leaf in sorted(subdirs):
            full = os.path.join(current, leaf)
            if os.path.islink(full):
                rel = os.path.relpath(full, root).replace(os.sep, "/")
                links[rel] = os.readlink(full)
            else:
                rel = os.path.relpath(full, root).replace(os.sep, "/")
                dirs.add(rel)
        for leaf in sorted(names):
            full = os.path.join(current, leaf)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if os.path.islink(full):
                links[rel] = os.readlink(full)
            else:
                files[rel] = digest(full)
                execs[rel] = bool(
                    os.lstat(full).st_mode & 0o100)
    return files, links, dirs, execs


def verify_source_archive(path, entries):
    """Verify the source archive equals the git tree at C.

    Returns the archived Cargo lock digests. Every file must match
    by bytes, every symlink by target, with no missing or extra
    entries; the owner-execute bit must match the git mode
    (100755 iff executable).
    """
    want_files = {entry["path"]: entry["sha256"]
                  for entry in entries if entry["kind"] == "file"}
    want_links = {entry["path"]: entry["target"]
                  for entry in entries if entry["kind"] == "symlink"}
    want_dirs = {entry["path"] for entry in entries
                 if entry["kind"] == "dir"}
    want_exec = {entry["path"]: entry["mode"] == "100755"
                 for entry in entries if entry["kind"] == "file"}
    with tempfile.TemporaryDirectory(
            prefix="candidate-source-") as tmp:
        root = safe_extract(path, Path(tmp) / "source", False, True)
        files, links, dirs, execs = walk_files(root)
    require(files == want_files, "source archive differs from C")
    require(links == want_links, "source archive differs from C")
    require(dirs == want_dirs, "source archive differs from C")
    require(execs == want_exec,
            "source archive modes differ from C")
    locks = {}
    for key, name in (("cargo_lock_sha256", "Cargo.lock"),
                      ("ebpf_lock_sha256",
                       "crates/ebpf/Cargo.lock")):
        require(name in files, "source archive lacks " + name)
        locks[key] = files[name]
    return locks


def verify_bundle_tarball(path, bundle_dir):
    """Verify the bundle tarball extracts to the bundle directory."""
    with tempfile.TemporaryDirectory(
            prefix="candidate-bundle-") as tmp:
        root = safe_extract(path, Path(tmp) / "bundle", True, False)
        files, links, _dirs, _execs = walk_files(root)
        require(not links, "bundle tarball carries symlinks")
        want, _, _, _ = walk_files(Path(bundle_dir))
    require(files == want, "bundle tarball differs from its directory")


def collect_payload_closure(root, harness_bin, bundle, deb, rpm):
    """Full copied-file closure via the release-entry harness.

    Runs an explicit harness binary when given, else `cargo run`
    in the source root under the repository pin. Returns the
    {logical path: sha256} map from the harness stdout.
    """
    if harness_bin is not None:
        harness = Path(harness_bin)
        require(not harness.is_symlink() and harness.is_file(),
                "harness binary is missing")
        argv = [str(harness), "payload-closure"]
        env = None
    else:
        argv = ["cargo", "run", "--manifest-path",
               str(Path(root) / "Cargo.toml"), "-p", HARNESS_PACKAGE,
               "--locked", "--offline", "--", "payload-closure"]
        env = {key: value for key, value in os.environ.items()
               if key != "RUSTUP_TOOLCHAIN"}
    argv += ["--bundle", str(bundle), "--deb", str(deb),
            "--rpm", str(rpm)]
    try:
        proc = subprocess.run(
            argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env=env, timeout=300)
    except OSError as error:
        raise ValueError(
            "cannot run payload closure: %s" % error) from error
    except subprocess.TimeoutExpired as error:
        raise ValueError(
            "payload closure timed out") from error
    if proc.returncode != 0:
        detail = proc.stderr.strip().splitlines()
        detail = detail[-1][:200] if detail else "exit %d" \
            % proc.returncode
        raise ValueError("payload closure failed: " + detail)
    try:
        closure = json.loads(proc.stdout, object_pairs_hook=unique)
    except ValueError as error:
        raise ValueError(
            "payload closure is not strict JSON") from error
    require(isinstance(closure, dict) and closure,
            "payload closure is empty")
    for name, value in closure.items():
        require(isinstance(name, str)
                and name.startswith(("bundle/", "deb/", "rpm/")),
                "invalid closure path")
        relative(name.split("/", 1)[1])
        hexid(value)
    return closure


def verify_sbom(sbom, files, artifacts):
    """Verify the SBOM binds the full closure and the containers."""
    require(isinstance(sbom, dict)
            and sbom.get("spdxVersion") == "SPDX-2.3",
            "unsupported SBOM")
    entries = sbom.get("files")
    require(isinstance(entries, list), "SBOM has no files")
    payload, seen = {}, set()
    for item in entries:
        require(isinstance(item, dict), "invalid SBOM file")
        name = item.get("fileName")
        require(isinstance(name, str) and name not in seen,
                "duplicate or invalid SBOM file")
        seen.add(name)
        checks = [check.get("checksumValue")
                  for check in item.get("checksums", [])
                  if isinstance(check, dict)
                  and check.get("algorithm") == "SHA256"]
        require(len(checks) == 1,
                "missing or ambiguous SBOM checksum")
        hexid(checks[0])
        if name.startswith("payload/"):
            payload[name[len("payload/"):]] = checks[0]
        else:
            parts = name.split("/", 2)
            require(len(parts) == 3 and parts[0] == "bundle"
                    and files.get(parts[2]) == checks[0],
                    "unknown SBOM copied file: " + name)
    require(payload == expected_payload({"files": files}),
            "SBOM payload closure mismatch")
    packages = sbom.get("packages")
    require(isinstance(packages, list), "SBOM has no packages")
    for entry in artifacts:
        if entry["role"] not in ("bundle", "deb", "rpm"):
            continue
        matches = [item for item in packages
                   if isinstance(item, dict)
                   and item.get("name") == entry["name"]]
        require(len(matches) == 1
                and matches[0].get("checksums") == [{
                    "algorithm": "SHA256",
                    "checksumValue": entry["sha256"]}],
                "SBOM container subject differs: " + entry["name"])


def verify_provenance(provenance, source, toolchain, files, subjects,
                      recorded):
    """Verify local-build provenance; return the receipt digest.

    The provenance record must repeat the sealed source/toolchain,
    its build receipt must equal the receipt the packager recorded
    in the bundle MANIFEST.json, name C and the presented
    engine/BPF bytes, and its subjects must bind the other five
    artifacts.
    """
    exact(provenance,
          {"schema", "origin", "source", "toolchain", "build_receipt",
           "subjects"}, "local provenance")
    require(provenance["schema"] == PROVENANCE_SCHEMA,
            "unsupported provenance schema %r"
            % (provenance.get("schema"),))
    require(provenance["origin"] == ORIGIN,
            "false provenance origin")
    require(provenance["source"] == source
            and provenance["toolchain"] == toolchain,
            "false provenance origin/source/toolchain")
    receipt = provenance["build_receipt"]
    exact(receipt,
          {"source_commit", "inventory_sha256", "tools", "outputs",
           "clean_tree", "built_from_source"},
          "build receipt")
    require(receipt == recorded,
            "provenance build receipt differs from the recorded "
            "build receipt")
    require(receipt["source_commit"] == source["commit"],
            "build receipt source differs from C")
    require(receipt["inventory_sha256"]
            == source["inventory_sha256"],
            "build receipt source differs from C")
    require(receipt["tools"] == toolchain["tools"],
            "build receipt tools differ")
    outputs = receipt["outputs"]
    exact(outputs, {"engine_sha256", "bpf"}, "build receipt outputs")
    require(outputs["engine_sha256"] == files.get("bin/memveil"),
            "build receipt engine differs from the bundle")
    require(isinstance(outputs["bpf"], dict)
            and set(outputs["bpf"]) == set(BPF_OBJECTS)
            and all(outputs["bpf"][name] == files.get("bpf/" + name)
                    for name in BPF_OBJECTS),
            "build receipt BPF differs from the bundle")
    require(provenance["subjects"] == subjects,
            "provenance subjects differ")
    return digest_canonical(receipt)


def create_manifest(bundle_dir, artifacts_dir, policy, source_info):
    """Seal the staged release outputs; return the manifest dict.

    source_info carries {"root": source checkout} plus an optional
    "harness_bin" path to the release-entry binary (without it the
    seal runs the harness via cargo in the root). Every artifact
    is verified against C and the bundle directory before its
    digest is bound; nothing is written.
    """
    require(isinstance(source_info, dict), "invalid source info")
    try:
        root = Path(source_info["root"])
    except (KeyError, TypeError) as error:
        raise ValueError("source info lacks the root") from error
    require(root.is_dir() and not root.is_symlink(),
            "source root is missing")
    harness_bin = source_info.get("harness_bin")
    commit = git(root, "rev-parse", "HEAD")
    hexid(commit, 40)
    tree = git(root, "rev-parse", commit + "^{tree}")
    hexid(tree, 40)
    require(not git(root, "status", "--porcelain",
                    "--untracked-files=all"),
            "candidate source must be clean")
    tools = probe_tool_versions(root)
    check_toolchain_pin(root, tools)
    bundled = verify_bundle_dir(bundle_dir)
    require(bundled["revision"] == commit,
            "bundle revision differs from the source commit")
    require(bundled["cargo_version"] == tools["cargo"]
            and bundled["rustc_version"] == tools["rustc"],
            "bundle toolchain record differs")
    recorded_linker = bundled["build_receipt"]["tools"]["bpf_linker"]
    require(recorded_linker == tools["bpf_linker"],
            "recorded bpf-linker %s differs from probed %s"
            % (recorded_linker, tools["bpf_linker"]))
    roles = discover_artifacts(artifacts_dir, bundled["manifest_bytes"])
    entries, inventory = git_inventory(root, commit)
    require(entries, "empty source inventory")
    locks = verify_source_archive(roles["source"], entries)
    require(locks["cargo_lock_sha256"] == bundled["lock_sha256"]
            and locks["ebpf_lock_sha256"]
            == bundled["ebpf_lock_sha256"],
            "source archive Cargo locks differ from the bundle")
    verify_bundle_tarball(roles["bundle"], bundle_dir)
    closure = collect_payload_closure(
        root, harness_bin, roles["bundle"], roles["deb"],
        roles["rpm"])
    require(closure == expected_payload({"files": bundled["files"]}),
            "package payload closure mismatch")
    records = []
    for role in sorted(ROLES):
        path = roles[role]
        require(not path.is_symlink() and path.is_file(),
                "artifact is not regular")
        records.append({"role": role, "name": path.name,
                        "size": str(path.stat().st_size),
                        "sha256": digest(path)})
    source = {"commit": commit, "tree": tree,
              "inventory_sha256": inventory}
    toolchain = {"cargo_lock_sha256": locks["cargo_lock_sha256"],
                 "ebpf_lock_sha256": locks["ebpf_lock_sha256"],
                 "tools": tools}
    verify_sbom(read_json(roles["sbom"]), bundled["files"], records)
    subjects = {entry["name"]: entry["sha256"] for entry in records
                if entry["role"] != "provenance"}
    receipt = verify_provenance(
        read_json(roles["provenance"], sealed=True), source,
        toolchain, bundled["files"], subjects,
        bundled["build_receipt"])
    for entry in records:
        verify_file(roles[entry["role"]], entry)
    policy_path = Path(policy)
    require(not policy_path.is_symlink()
            and policy_path.is_file(),
            "policy must be a regular file")
    doc = {"schema": SCHEMA, "origin": ORIGIN, "source": source,
           "toolchain": toolchain, "build_receipt_sha256": receipt,
           "bundle_manifest_sha256":
           bundled["manifest_sha256"],
           "policy_sha256": digest(policy_path),
           "files": bundled["files"], "artifacts": records}
    return validate_manifest(doc)


def emit_provenance(bundle_dir, source_info, out_path):
    """Compose local-build provenance from the recorded receipt.

    source_info carries {"root": source checkout} plus one path per
    subject role ("bundle", "deb", "rpm", "source", "sbom"). Every
    value is re-verified, never trusted: the source comes from git
    at C, the toolchain from the probed tools plus the bundle lock
    record, the receipt is copied verbatim from the bundle
    MANIFEST.json recording (and must name C, the probed tools, and
    the presented engine/BPF bytes), and the subjects are the
    digests of the presented artifact bytes. Writes the canonical
    provenance once (FileExistsError on overwrite) and returns its
    digest. The seal re-verifies every bound artifact; the emitter
    only binds their true digests.
    """
    require(isinstance(source_info, dict), "invalid source info")
    try:
        root = Path(source_info["root"])
    except (KeyError, TypeError) as error:
        raise ValueError("source info lacks the root") from error
    require(root.is_dir() and not root.is_symlink(),
            "source root is missing")
    roles = {}
    for role in ("bundle", "deb", "rpm", "source", "sbom"):
        try:
            path = Path(source_info[role])
        except (KeyError, TypeError) as error:
            raise ValueError(
                "source info lacks the %s path" % role) from error
        require(not path.is_symlink() and path.is_file(),
                "subject must be a regular file: " + role)
        roles[role] = path
    commit = git(root, "rev-parse", "HEAD")
    hexid(commit, 40)
    tree = git(root, "rev-parse", commit + "^{tree}")
    hexid(tree, 40)
    require(not git(root, "status", "--porcelain",
                    "--untracked-files=all"),
            "provenance source must be clean")
    tools = probe_tool_versions(root)
    check_toolchain_pin(root, tools)
    bundled = verify_bundle_dir(bundle_dir)
    require(bundled["revision"] == commit,
            "bundle revision differs from the source commit")
    require(bundled["cargo_version"] == tools["cargo"]
            and bundled["rustc_version"] == tools["rustc"],
            "bundle toolchain record differs")
    recorded = bundled["build_receipt"]
    require(recorded["tools"] == tools,
            "recorded build tools differ from the probed toolchain")
    entries, inventory = git_inventory(root, commit)
    require(entries, "empty source inventory")
    require(recorded["source_commit"] == commit
            and recorded["inventory_sha256"] == inventory,
            "build receipt source differs from C")
    subjects = {path.name: digest(path)
                for role, path in sorted(roles.items())}
    require(len(subjects) == len(roles),
            "subject artifact names must be distinct")
    source = {"commit": commit, "tree": tree,
              "inventory_sha256": inventory}
    toolchain = {"cargo_lock_sha256": bundled["lock_sha256"],
                 "ebpf_lock_sha256": bundled["ebpf_lock_sha256"],
                 "tools": tools}
    provenance = {"schema": PROVENANCE_SCHEMA, "origin": ORIGIN,
                  "source": source, "toolchain": toolchain,
                  "build_receipt": recorded, "subjects": subjects}
    data = canonical(provenance)
    write_once(out_path, data)
    return digest_bytes(data)


def evidence_only_path(path):
    """True when a tree path may change in an evidence commit."""
    if path == EVIDENCE_TESTED:
        return True
    if not path.startswith(EVIDENCE_QUALIFICATIONS):
        return False
    leaf = path[len(EVIDENCE_QUALIFICATIONS):]
    return "/" not in leaf and leaf.endswith(".json") \
        and len(leaf) > len(".json")


def _git_bytes(root, *args):
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), *args],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=git_env())
    except OSError as error:
        raise ValueError("cannot run git: %s" % error) from error
    require(proc.returncode == 0,
            "git %s failed" % " ".join(args[:2]))
    return proc.stdout


def _git_paths(root, *args):
    """Decode a -z git path list; refuse undecodable names."""
    paths = []
    for entry in _git_bytes(root, *args).split(b"\0"):
        if not entry:
            continue
        try:
            paths.append(entry.decode("utf-8"))
        except UnicodeError as error:
            raise ValueError(
                "invalid tree path encoding") from error
    return paths


def _verify_q_diff(root, c_commit, q_commit):
    hexid(c_commit, 40)
    hexid(q_commit, 40)
    git(root, "merge-base", "--is-ancestor", c_commit, q_commit)
    # Check every commit, so an intermediate source edit cannot be
    # hidden by a revert.
    commits = git(root, "rev-list", c_commit + ".." + q_commit)
    for commit in commits.splitlines():
        parents = git(root, "rev-list", "--parents", "-n", "1",
                      commit).split()[1:]
        require(len(parents) == 1,
                "evidence-only history cannot contain merges")
        for path in _git_paths(root, "diff", "--name-only",
                               "--no-renames", "-z", parents[0],
                               commit):
            require(evidence_only_path(path),
                    "Q is not evidence-only: " + path)


def verify_q_diff(c_commit, q_commit):
    """Require Q to be evidence-only over C in this checkout.

    Runs in the current working directory, which must be the
    source checkout. Only packaging/tested-payload.sha256 and
    packaging/qualifications/*.json may change; merges fail.
    Returns None; raises ValueError otherwise.
    """
    _verify_q_diff(".", c_commit, q_commit)
    return None


def verify_q_bound(manifest, c_commit, q_commit, checkout_root):
    """Bind a loaded manifest to its dispatched source and Q.

    Requires manifest["source"]["commit"] == c_commit and Q
    evidence-only over C in checkout_root: a manifest sealing
    a different source, or a Q carrying non-evidence edits,
    fails closed even when the policy and lock bytes match.
    Returns None; raises ValueError otherwise.
    """
    source = manifest.get("source") \
        if isinstance(manifest, dict) else None
    sealed = source.get("commit") \
        if isinstance(source, dict) else None
    require(sealed == c_commit,
            "manifest source differs from the dispatched "
            "source commit")
    _verify_q_diff(checkout_root, c_commit, q_commit)
    return None


def verify_signature(subject, signature, public_key, trusted):
    """Verify an ssh-keygen -Y Ed25519 signature over subject."""
    require(digest(public_key) in trusted,
            "untrusted signing key")
    data = read_regular(subject)
    read_regular(signature)
    try:
        key = read_regular(public_key).decode().strip()
    except UnicodeError as error:
        raise ValueError("unsupported signing key") from error
    require(key.startswith("ssh-ed25519 ")
            and "\n" not in key, "unsupported signing key")
    with tempfile.TemporaryDirectory(
            prefix="candidate-trust-") as tmp:
        allowed = Path(tmp) / "allowed"
        allowed.write_text("qualifier " + key + "\n")
        result = subprocess.run(
            ["ssh-keygen", "-Y", "verify", "-f", str(allowed),
             "-I", "qualifier", "-n", SIGNING_NAMESPACE,
             "-s", str(signature)],
            input=data, capture_output=True)
    require(result.returncode == 0,
            "signature verification failed")


def validate_policy(path):
    """Read, hash, and validate the candidate policy from one read.

    The file bytes are read exactly once; hashing and parsing
    consume those same bytes, so the returned digest binds the
    validated document and no later re-read can substitute it.
    Returns (policy, digest_hex); raises ValueError otherwise.
    """
    data = read_regular(path)
    policy = _parse_json(data)
    exact(policy, {"schema", "claim", "required_gates",
                   "trusted_keys", "retention_days"}, "policy")
    require(policy["schema"] == POLICY_SCHEMA,
            "unsupported candidate policy")
    require(policy["claim"] in ("ordinary-preview", "snp-journal",
                                "security-workflow"),
            "unsupported release claim")
    require(isinstance(policy["trusted_keys"], list),
            "invalid trusted keys")
    for key in policy["trusted_keys"]:
        hexid(key)
    require(30 <= parse_size(policy["retention_days"]) <= 90,
            "campaign retention must be 30 to 90 days")
    require(isinstance(policy["required_gates"], dict)
            and policy["required_gates"],
            "required gates are empty")
    for ident, gate in policy["required_gates"].items():
        require(re.fullmatch(GATE_ID_RE, ident),
                "gate IDs must be versioned")
        require(isinstance(gate, dict)
                and {"environment", "predicates"} <= set(gate)
                <= {"environment", "predicates", "limits",
                    "adapter"},
                "gate policy has invalid fields")
        require(gate.get("adapter") in (None, "paced-replay/1"),
                "unknown gate adapter")
        require(isinstance(gate["predicates"], dict)
                and gate["predicates"],
                "empty required predicates")
        for name, operation in gate["predicates"].items():
            require(re.fullmatch(r"[a-z][a-z0-9_-]*", name)
                    and operation in ("equal", "zero",
                                      "at-most", "at-least"),
                    "invalid gate predicate")
        limits = gate.get("limits", {})
        require(isinstance(limits, dict), "invalid gate limits")
        for name, value in limits.items():
            require(name in gate["predicates"],
                    "limit without predicate")
            parse_size(value)
        require(gate["environment"] in ("offline",
                                        "ordinary-linux", "snp",
                                        "tdx", "hyperv"),
                "unknown gate environment")
    environments = {gate["environment"]
                    for gate in
                    policy["required_gates"].values()}
    if policy["claim"] != "ordinary-preview":
        require("snp" in environments,
                "SNP qualification required")
    if policy["claim"] == "security-workflow":
        require({"tdx", "hyperv"} <= environments,
                "TDX and Hyper-V qualification required")
    return policy, digest_bytes(data)


def verify_measurement_sources(record, base):
    sources = record.get("sources")
    exact(sources, {"product", "oracle"},
          "retained measurement sources")
    product_files = {binding["file"]
                     for binding in sources["product"].values()}
    oracle_files = {binding["file"]
                    for binding in sources["oracle"].values()}
    require(not product_files & oracle_files,
            "product and oracle measurements require separate "
            "retained sources")
    for side in ("product", "oracle"):
        exact(sources[side], record[side],
              side + " source bindings")
        for name, binding in sources[side].items():
            exact(binding, {"file", "sha256", "path",
                            "encoding"},
                  "measurement source binding")
            path = Path(base) / relative(binding["file"])
            data = read_regular(path)
            require(digest_bytes(data)
                    == hexid(binding["sha256"]),
                    "retained measurement file changed")
            value = read_json(path)
            require(canonical(value)
                    == canonical(json.loads(
                        data, object_pairs_hook=unique)),
                    "measurement file changed while reading")
            require(isinstance(binding["path"], list)
                    and len(binding["path"]) <= 64,
                    "invalid measurement path")
            for key in binding["path"]:
                require((isinstance(value, dict)
                         and isinstance(key, str)
                         and key in value)
                        or (isinstance(value, list)
                            and type(key) is int
                            and 0 <= key < len(value)),
                        "measurement path absent")
                value = value[key]
            if binding["encoding"] == "boolean":
                require(type(value) is bool,
                        "measurement boolean required")
                value = "1" if value else "0"
            else:
                require(binding["encoding"] == "u64"
                        and (type(value) is int
                             or isinstance(value, str)),
                        "unsigned measurement required")
                value = str(value)
                parse_size(value)
            require(value == record[side][name],
                    "retained measurement differs: " + side
                    + "/" + name)


def rederive_measurements(record, requirement):
    require(set(record) in ({"schema", "environment", "product",
                              "oracle"},
                             {"schema", "environment", "product",
                              "oracle", "sources"}),
            "gate inputs have invalid fields")
    require(record["schema"] == GATE_INPUT_SCHEMA,
            "unsupported gate input schema")
    require(record["environment"] == requirement["environment"],
            "gate environment mismatch")
    predicates = requirement["predicates"]
    require(bool(predicates), "empty gate predicates")
    exact(record["product"], predicates, "product measurements")
    exact(record["oracle"], predicates, "oracle measurements")
    for name, operation in predicates.items():
        actual = parse_size(record["product"][name])
        expected = parse_size(record["oracle"][name])
        if name in requirement.get("limits", {}):
            require(record["oracle"][name]
                    == requirement["limits"][name],
                    "oracle threshold differs from fixed "
                    "policy: " + name)
        if operation == "equal":
            require(actual == expected and expected > 0,
                    "oracle counts differ: " + name)
        elif operation == "zero":
            require(actual == expected == 0,
                    "loss or cleanup failure: " + name)
        elif operation == "at-least":
            require(actual >= expected > 0,
                    "minimum measurement failed: " + name)
        elif operation == "at-most":
            require(actual <= expected and expected > 0,
                    "maximum measurement failed: " + name)
        else:
            raise ValueError("unknown oracle predicate")
    if requirement.get("adapter") == "paced-replay/1":
        actual, oracle = record["product"], record["oracle"]
        minimum = (parse_size(oracle["read_bytes"]) + 65535) \
            // 65536 + 1
        require(parse_size(oracle["read_calls"]) == minimum
                and parse_size(actual["read_calls"])
                >= minimum,
                "real read/EOF calls were not proven")
        require(parse_size(actual["rss_bytes"]) > 0,
                "RSS measurement is absent")
        require(parse_size(actual["max_request_bytes"]) > 0,
                "read request measurement is absent")
    return True


def _matrix_rows():
    """Row-allowlist oracle from tests/vm/kernel_matrix.py (lazy)."""
    vmdir = str(Path(__file__).resolve().parents[1]
                / "tests" / "vm")
    if vmdir not in sys.path:
        sys.path.insert(0, vmdir)
    import kernel_matrix
    return kernel_matrix


def _live_campaigns():
    """Installed-campaign verifier from tests/vm/candidate_live.py (lazy)."""
    vmdir = str(Path(__file__).resolve().parents[1]
                / "tests" / "vm")
    if vmdir not in sys.path:
        sys.path.insert(0, vmdir)
    import candidate_live
    return candidate_live


def _resolve_live_files(retained, base):
    """Campaign bytes resolved only through signed digests.

    Every live scalar binding must name its campaign's own
    export file (product: live/<mode>/campaign.json, oracle:
    live/<mode>-exit.json); a binding naming any other file
    is a wrong-file replay and refuses, as do disagreeing
    digests for one file or bytes that fail the signed
    digest. Returns {relpath: bytes} for the four campaign
    files. Raises ValueError otherwise.
    """
    sources = retained.get("sources")
    require(isinstance(sources, dict),
            "live campaign bindings are missing")
    resolved = {}
    for mode in LIVE_CAMPAIGNS:
        for side, leaf in (
                ("product", "live/%s/campaign.json" % mode),
                ("oracle", "live/%s-exit.json" % mode)):
            bindings = sources.get(side)
            require(isinstance(bindings, dict),
                    "live campaign bindings are missing")
            digests = set()
            for name in LIVE_TOTALS:
                binding = bindings.get("%s_%s" % (mode, name))
                require(isinstance(binding, dict)
                        and binding.get("file") == leaf,
                        "live %s replay resolves outside "
                        "the campaign export" % mode)
                digests.add(hexid(binding.get("sha256")))
            require(len(digests) == 1,
                    "live %s bindings disagree" % mode)
            try:
                data = read_regular(Path(base) / relative(leaf))
            except OSError as error:
                raise ValueError(
                    "live %s evidence is missing" % leaf) \
                    from error
            require(digest_bytes(data) == digests.pop(),
                    "live %s file changed" % leaf)
            resolved[leaf] = data
    return resolved


def verify_live_campaigns(retained, base, manifest):
    """Re-verify both retained live campaigns from bytes.

    The live gate binds the overhead and soak campaigns'
    totals as <campaign>_<total> product/oracle scalars,
    so pool-only evidence can never satisfy it. The four
    campaign files resolve only through the signed source
    digests: no replay file opens by bare path, and every
    compared byte traces to a signed digest. Each
    live/<campaign> export must pass the campaign
    verifier under its requested mode, and the verified
    totals must equal the bound scalars on both sides.
    The host exit.json beside each export must name the
    candidate, record an integer guest exit of zero, and
    carry host totals equal to the replayed totals. Runs
    after the scalar re-derivation, which owns the inputs
    shape. Raises ValueError otherwise.
    """
    live = _live_campaigns()
    files = _resolve_live_files(retained, base)
    candidate_id = digest_bytes(canonical(manifest))
    for mode in LIVE_CAMPAIGNS:
        try:
            totals = live.verify_live_campaign(
                Path(base) / "live" / mode, manifest, mode,
                files["live/%s/campaign.json" % mode])
        except (OSError, ValueError) as error:
            raise ValueError(
                "live %s evidence refuses: %s"
                % (mode, error)) from error
        for side in ("product", "oracle"):
            for name in LIVE_TOTALS:
                key = "%s_%s" % (mode, name)
                require(retained[side].get(key)
                        == totals[name],
                        "live %s %s differs from retained "
                        "bytes" % (side, key))
        try:
            exit_doc = json.loads(
                files["live/%s-exit.json" % mode],
                object_pairs_hook=unique)
        except ValueError as error:
            raise ValueError(
                "live %s oracle is missing" % mode) from error
        require(isinstance(exit_doc, dict)
                and exit_doc.get("candidate") == candidate_id,
                "live %s oracle names another candidate"
                % mode)
        raw_exit = exit_doc.get("guest_exit")
        try:
            coerced_exit = int(raw_exit)
        except (TypeError, ValueError):
            raise ValueError(
                "live %s guest exit refuses" % mode)
        require(type(raw_exit) is int
                and coerced_exit == 0,
                "live %s guest exit refuses" % mode)
        require(exit_doc.get("totals") == totals,
                "live %s host totals differ from replay"
                % mode)


def _required_evidence(path, label):
    """Digest of a required evidence file; ValueError when absent."""
    try:
        mode = os.lstat(path).st_mode
    except OSError as error:
        raise ValueError(
            "matrix evidence is missing required file: "
            + label) from error
    require(stat.S_ISREG(mode),
            "matrix evidence requires a regular file: "
            + label)
    try:
        data = read_regular(path)
    except OSError as error:
        raise ValueError(
            "matrix evidence is missing required file: "
            + label) from error
    return digest_bytes(data)


def _row_inventory_files(allowlist, row):
    """{relpath: sha256} for one matrix row directory.

    Every retained file must be allowlisted row evidence; the row
    receipt and cached oracle inputs are required and hashed
    explicitly, since their bytes are evidence while the row-local
    transcription inventory never authenticates itself. The raw
    boot command line stays local-only: skipped here, skipped
    by the redaction replay, and excluded from the evidence
    archive builder, matching the row receipt construction.
    """
    found = {}
    for dirpath, dirnames, filenames in os.walk(row):
        for name in sorted(dirnames):
            target = Path(dirpath) / name
            if os.path.islink(target):
                raise ValueError(
                    "matrix row refuses symlinked directory %s"
                    % target.relative_to(row).as_posix())
        for name in sorted(filenames):
            path = Path(dirpath) / name
            rel = path.relative_to(row).as_posix()
            if rel in ("receipt.json", "oracle-inputs.json",
                       "vng-cmd.txt"):
                continue
            if path.is_symlink() or not path.is_file():
                raise ValueError(
                    "matrix row refuses non-file %s" % rel)
            if not allowlist(rel):
                raise ValueError(
                    "matrix row refuses unknown file %s" % rel)
            try:
                found[rel] = digest(path)
            except OSError as error:
                raise ValueError(
                    "matrix row cannot hash %s" % rel) from error
    label = Path(row).name
    for required in ("receipt.json", "oracle-inputs.json"):
        found[required] = _required_evidence(
            Path(row) / required, label + "/" + required)
    return found


def build_evidence_inventory(evidence_dir, matrix_directory):
    """Map every consumed matrix evidence file to its SHA-256.

    Keys are matrix-relative POSIX paths: per-row receipt.json,
    oracle-inputs.json and retained raws, the <id>.json sidecar
    recs the tested export re-derives against, plus
    summary.json and, when the campaign retained them, the
    MATRIX_RUNNER_FILES outputs (harness.json, summary.txt).
    A sidecar is admitted only when it names a retained row
    directory, so unrelated files still fail as extra. The
    signed gate receipt stays outside its own inventory, so
    the binding is noncircular. Raises ValueError on missing,
    extra, unknown, or non-regular evidence.
    """
    base = Path(evidence_dir)
    mdir = base / relative(matrix_directory)
    if mdir.is_symlink() or not mdir.is_dir():
        raise ValueError(
            "matrix evidence directory is missing: "
            + matrix_directory)
    allowlist = _matrix_rows()._row_rel_known
    inventory = {}
    names = sorted(os.listdir(mdir))
    modes = {}
    for name in names:
        mode = os.lstat(mdir / name).st_mode
        if stat.S_ISLNK(mode):
            raise ValueError(
                "matrix evidence refuses symlink: " + name)
        modes[name] = mode
    rows = {name for name, mode in modes.items()
            if stat.S_ISDIR(mode)}
    for name in names:
        full = mdir / name
        mode = modes[name]
        if stat.S_ISDIR(mode):
            for rel, found in sorted(
                    _row_inventory_files(allowlist,
                                         full).items()):
                inventory[name + "/" + rel] = found
        elif stat.S_ISREG(mode) and name == "summary.json":
            inventory["summary.json"] = _required_evidence(
                full, "summary.json")
        elif stat.S_ISREG(mode) and name.endswith(".json") \
                and name[:-5] in rows:
            inventory[name] = _required_evidence(full, name)
        elif stat.S_ISREG(mode) and name in MATRIX_RUNNER_FILES:
            try:
                inventory[name] = digest(full)
            except OSError as error:
                raise ValueError(
                    "matrix evidence cannot hash: "
                    + name) from error
        else:
            raise ValueError(
                "matrix evidence has an extra file: " + name)
    if "summary.json" not in inventory:
        raise ValueError(
            "matrix evidence is missing required file: "
            "summary.json")
    return inventory


def build_evidence_archive(evidence_dir, dest):
    """Pack qualification evidence, excluding local-only files.

    Writes dest as a gzip tar holding the evidence directory
    under a single "evidence" root in sorted order, so the
    archive extracts through safe_extract's single-root gate.
    Row-local files (the matrix REDACT_SKIP_LOCAL set,
    resolved lazily like the row allowlist) are excluded at
    any depth: host command lines never ship. An
    evidence-root qualification.json is refused outright: the
    archive-digest record lives beside the archive, never
    inside it. Symlinks and non-regular files fail closed
    instead of silently dropping bytes, and a failed run
    leaves no partial archive behind. Refuses to overwrite
    dest. Returns the sorted excluded evidence-relative
    paths.
    """
    excluded_names = set(_matrix_rows().REDACT_SKIP_LOCAL)
    base = Path(evidence_dir)
    require(base.is_dir() and not base.is_symlink(),
            "evidence directory is missing")
    dest = Path(dest)
    require(not os.path.lexists(dest),
            "refusing to overwrite " + dest.name)
    dirs = []
    entries = []
    excluded = []
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames.sort()
        here = Path(dirpath)
        rel = here.relative_to(base).as_posix()
        if rel != ".":
            dirs.append((rel, here))
        for name in sorted(dirnames):
            if os.path.islink(here / name):
                raise ValueError(
                    "evidence archive refuses symlink "
                    + (here / name).relative_to(base)
                    .as_posix())
        for name in sorted(filenames):
            path = here / name
            member = path.relative_to(base).as_posix()
            if member == "qualification.json":
                raise ValueError(
                    "evidence archive refuses the inner "
                    "qualification record: it lives beside "
                    "the archive, never inside it")
            if name in excluded_names:
                excluded.append(member)
                continue
            if path.is_symlink():
                raise ValueError(
                    "evidence archive refuses symlink "
                    + member)
            if not path.is_file():
                raise ValueError(
                    "evidence archive refuses non-file "
                    + member)
            entries.append((member, path))
    try:
        with tarfile.open(dest, "w:gz") as stream:
            stream.add(base, arcname="evidence",
                       recursive=False)
            for rel, full in sorted(dirs):
                stream.add(full, arcname="evidence/" + rel,
                           recursive=False)
            for rel, full in sorted(entries):
                stream.add(full, arcname="evidence/" + rel,
                           recursive=False)
    except (tarfile.TarError, OSError) as error:
        try:
            os.unlink(dest)
        except OSError:
            pass
        raise ValueError(
            "evidence archive failed: %s" % error) from error
    return sorted(excluded)


def _matrix_lock_from_tree(source_tree, commit):
    """Parse the matrix lock from C's tree bytes.

    Reads tests/vm/kernels.lock.json at the candidate source
    commit from the given checkout without checking anything
    out, so the required row set is pinned by C itself. The
    bytes then run the shared full-grammar validation the
    tested export runs, so a malformed lock schema is refused
    here instead of only at export. Returns the parsed lock;
    raises ValueError otherwise.
    """
    hexid(commit, 40)
    try:
        proc = subprocess.run(
            ["git", "-C", str(source_tree), "show",
             "%s:tests/vm/kernels.lock.json" % commit],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=git_env())
    except OSError as error:
        raise ValueError(
            "cannot read the source matrix lock: %s"
            % error) from error
    require(proc.returncode == 0,
            "source tree has no matrix lock at " + commit)
    lock = _parse_json(proc.stdout)
    _matrix_rows().parse_lock_bytes(proc.stdout)
    return lock


def verify_evidence_inventory(inputs, evidence_dir):
    """Recompute the matrix inventory; reject altered evidence.

    Every digest is recomputed from the evidence bytes and the
    canonical inventory must equal the signed digest exactly, so
    altered, missing, or extra files fail before any evaluation.
    Returns None; raises ValueError otherwise.
    """
    exact(inputs, {"schema", "matrix_directory",
                   "evidence_inventory_sha256"},
          "matrix inputs")
    require(inputs["schema"] == MATRIX_INPUT_SCHEMA,
            "unsupported matrix input schema %r: /1 inputs "
            "fail closed" % (inputs.get("schema"),))
    pinned = hexid(inputs["evidence_inventory_sha256"])
    rebuilt = build_evidence_inventory(
        evidence_dir, inputs["matrix_directory"])
    require(digest_canonical(rebuilt) == pinned,
            "matrix evidence inventory differs from the "
            "signed inputs")
    return None


def verify_qualification(candidate, qualification, policy,
                         evidence_dir, source_tree="."):
    """Rederive every required signed gate over an evidence dir.

    For the matrix gate the evidence inventory digests are
    verified before the signature, the signature before any
    predicate, and predicates before export; other gates verify
    the signature chain, then retained measurements, then
    predicates. The matrix row set comes from the lock at C in
    the source tree, and every required row re-runs the
    same shared row verification the tested export runs
    (receipt consistency plus predicates). Returns
    {"ok": True, "gates": [...], "trusted_keys": [...],
    "claim": ...} with the verified gate IDs sorted and the
    validated policy's pinned trust and claim; raises
    ValueError otherwise. Callers reuse the returned trust and
    claim instead of re-reading the policy file, so the bytes
    verified here are the bytes used downstream. The
    qualification's evidence_archive entry is shape-checked
    only: archive bytes are verified by whoever extracts them.
    The archive-digest record lives beside the evidence
    archive, never inside it: a qualification consumed from
    inside its own evidence dir is the old self-referential
    layout (unconstructable honestly, since the digest would
    bind bytes containing the digest) and fails closed here,
    so every path through this verifier (qualify, export,
    import) uses the external layout.
    """
    manifest = load_manifest(candidate)
    candidate_id = digest(candidate)
    validated, policy_digest = validate_policy(policy)
    require(policy_digest == manifest["policy_sha256"],
            "policy differs from candidate")
    doc = read_json(qualification, sealed=True)
    exact(doc, {"schema", "candidate_sha256", "source_commit",
                "claim", "gates", "evidence_archive"},
          "qualification")
    require(doc["schema"] == QUALIFICATION_SCHEMA
            and doc["candidate_sha256"] == candidate_id
            and doc["source_commit"]
            == manifest["source"]["commit"]
            and doc["claim"] == validated["claim"],
            "qualification subject mismatch")
    exact(doc["gates"], validated["required_gates"],
          "required qualification gates")
    archive = doc["evidence_archive"]
    exact(archive, {"name", "size", "sha256"},
          "evidence archive")
    relative(archive["name"])
    parse_size(archive["size"])
    hexid(archive["sha256"])
    base = Path(evidence_dir)
    try:
        nested = Path(qualification).resolve().relative_to(
            base.resolve())
    except ValueError:
        nested = None
    require(nested is None,
            "qualification must live beside the evidence "
            "archive, never inside it")
    for ident in sorted(doc["gates"]):
        gate = doc["gates"][ident]
        exact(gate, {"receipt", "receipt_sha256", "signature",
                     "public_key"},
              "gate receipt binding")
        for key in ("receipt", "signature", "public_key"):
            relative(gate[key])
        receipt = base / gate["receipt"]
        if ident == MATRIX_GATE:
            record = read_json(receipt, sealed=True)
            exact(record,
                  {"schema", "gate", "candidate_sha256",
                   "source_commit", "inputs", "inputs_sha256"},
                  "signed gate receipt")
            relative(record["inputs"])
            retained = read_json(base / record["inputs"],
                                 sealed=True)
            verify_evidence_inventory(retained, base)
            require(digest(receipt)
                    == hexid(gate["receipt_sha256"]),
                    "retained receipt changed")
            verify_signature(receipt, base / gate["signature"],
                             base / gate["public_key"],
                             validated["trusted_keys"])
            require(record["schema"] == GATE_RECEIPT_SCHEMA
                    and record["gate"] == ident
                    and record["candidate_sha256"]
                    == candidate_id
                    and record["source_commit"]
                    == manifest["source"]["commit"],
                    "gate subject mismatch")
            require(digest(base / record["inputs"])
                    == hexid(record["inputs_sha256"]),
                    "retained gate inputs changed")
            lock = _matrix_lock_from_tree(
                source_tree, manifest["source"]["commit"])
            _matrix_rows().verify_tested_rows(
                base / relative(retained["matrix_directory"]),
                lock, manifest)
        else:
            require(digest(receipt)
                    == hexid(gate["receipt_sha256"]),
                    "retained receipt changed")
            verify_signature(receipt, base / gate["signature"],
                             base / gate["public_key"],
                             validated["trusted_keys"])
            record = read_json(receipt, sealed=True)
            exact(record,
                  {"schema", "gate", "candidate_sha256",
                   "source_commit", "inputs", "inputs_sha256"},
                  "signed gate receipt")
            require(record["schema"] == GATE_RECEIPT_SCHEMA
                    and record["gate"] == ident
                    and record["candidate_sha256"]
                    == candidate_id
                    and record["source_commit"]
                    == manifest["source"]["commit"],
                    "gate subject mismatch")
            relative(record["inputs"])
            inputs = base / record["inputs"]
            require(digest(inputs)
                    == hexid(record["inputs_sha256"]),
                    "retained gate inputs changed")
            retained = read_json(inputs, sealed=True)
            verify_measurement_sources(retained, base)
            rederive_measurements(
                retained,
                validated["required_gates"][ident])
            if ident == LIVE_GATE:
                verify_live_campaigns(retained, base,
                                      manifest)
    return {"ok": True, "gates": sorted(doc["gates"]),
            "trusted_keys": list(validated["trusted_keys"]),
            "claim": validated["claim"]}


def checksums_text(artifacts_dir):
    """Render the sorted "<sha>  <name>" lines for a directory.

    Every entry must be a regular file; symlinks, directories,
    newline names, and an empty directory fail closed. Shared by
    the signer and the verifier so the two cannot drift.
    """
    directory = Path(artifacts_dir)
    require(directory.is_dir() and not directory.is_symlink(),
            "artifacts directory is missing")
    leaves = sorted(os.listdir(directory))
    require(leaves, "no artifacts to sign")
    lines = []
    for leaf in leaves:
        require("\n" not in leaf, "invalid artifact name")
        fd = os.open(directory / leaf,
                     os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode),
                    "artifact is not a regular file: " + leaf)
            found = hashlib.sha256()
            for chunk in iter(lambda: stream.read(1048576),
                              b""):
                found.update(chunk)
        lines.append(found.hexdigest() + "  " + leaf + "\n")
    return "".join(lines)


def sign_checksums(artifacts_dir, key_path, out_dir):
    """Hash staged artifacts, write SHA256SUMS.txt, sign it.

    Writes SHA256SUMS.txt (the exact sorted lines), its
    ssh-keygen -Y signature over the candidate namespace, and
    signer.pub (the Ed25519 key derived from the private key),
    then self-verifies the triple. Every write refuses to
    overwrite; a failed run leaves no partial triple behind.
    Returns the SHA256SUMS.txt digest hex.
    """
    text = checksums_text(artifacts_dir)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    sums = out / "SHA256SUMS.txt"
    signature = out / "SHA256SUMS.txt.sig"
    public = out / "signer.pub"
    for path in (signature, public):
        require(not os.path.lexists(path),
                "refusing to overwrite " + path.name)
    created = []
    done = False
    try:
        write_once(sums, text.encode())
        created.append(sums)
        signed = subprocess.run(
            ["ssh-keygen", "-Y", "sign", "-f", str(key_path),
             "-n", SIGNING_NAMESPACE, str(sums)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        require(signed.returncode == 0,
                "checksum signing failed")
        created.append(signature)
        derived = subprocess.run(
            ["ssh-keygen", "-y", "-f", str(key_path)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        require(derived.returncode == 0,
                "cannot read signing key")
        try:
            key = derived.stdout.decode().strip()
        except UnicodeError as error:
            raise ValueError(
                "unsupported signing key") from error
        require(key.startswith("ssh-ed25519 ")
                and "\n" not in key, "unsupported signing key")
        write_once(public, (key + "\n").encode())
        created.append(public)
        verify_signature(sums, signature, public,
                         [digest(public)])
        done = True
    finally:
        if not done:
            for path in created:
                try:
                    os.unlink(path)
                except OSError:
                    pass
            # A failed ssh-keygen run may still leave a partial
            # .sig behind before the success path records it; the
            # pre-check above guarantees any such file is ours.
            try:
                os.unlink(signature)
            except OSError:
                pass
    return digest_bytes(text.encode())


def verify_artifact_checksums(artifacts_dir, sums_path):
    """Re-derive the checksums; require the sums file to match.

    A substituted artifact, an added file, or a dropped file
    fails closed. Returns the re-derived text.
    """
    expected = checksums_text(artifacts_dir)
    require(read_regular(sums_path) == expected.encode(),
            "signed checksums differ from artifacts")
    return expected


def verify_signed_checksums(manifest, evidence, trusted):
    """Verify the signed artifact checksums against the manifest."""
    evidence = Path(evidence)
    verify_signature(evidence / "SHA256SUMS.txt",
                     evidence / "SHA256SUMS.txt.sig",
                     evidence / "signer.pub", trusted)
    expected = "".join(
        entry["sha256"] + "  " + entry["name"] + "\n"
        for entry in sorted(manifest["artifacts"],
                            key=lambda entry: entry["name"]))
    require(read_regular(evidence / "SHA256SUMS.txt")
            == expected.encode(),
            "signed checksums differ from candidate")
    return expected


def verify_tested_payload(manifest, tested_path):
    """Verify a tested-payload file against the candidate closure."""
    try:
        text = read_regular(tested_path).decode()
    except UnicodeError as error:
        raise ValueError(
            "invalid tested payload line") from error
    entries = {}
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split()
        require(len(parts) == 2, "invalid tested payload line")
        found, name = parts
        hexid(found)
        require(name not in entries,
                "duplicate tested payload entry")
        entries[name] = found
    require(entries == expected_payload(manifest),
            "Q tested payload differs from candidate closure")
    return entries


def remote_id(value):
    """Immutable remote decimal ID: no zero, no leading zeros."""
    require(isinstance(value, str)
            and re.fullmatch(r"[1-9][0-9]*", value),
            "invalid immutable remote ID")
    return value


def remote_repository(value):
    """Owner/name repository identity."""
    require(isinstance(value, str)
            and re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+",
                             value),
            "invalid repository")
    return value


def validate_inputs_doc(doc):
    """Shape-check one gate inputs document for authoring.

    Matrix inputs need their exact inventory binding; other
    gates need rederivation-shaped measurements with
    shape-checked source bindings. Retained bytes are bound
    at assembly, never here: receipt authoring takes no
    evidence directory. Returns "matrix" or "gate".
    """
    require(isinstance(doc, dict),
            "gate inputs must be an object")
    schema = doc.get("schema")
    if schema == MATRIX_INPUT_SCHEMA:
        exact(doc, {"schema", "matrix_directory",
                    "evidence_inventory_sha256"},
              "matrix inputs")
        relative(doc["matrix_directory"])
        hexid(doc["evidence_inventory_sha256"])
        return "matrix"
    require(schema == GATE_INPUT_SCHEMA,
            "unsupported gate input schema %r: /1 inputs "
            "fail closed" % (schema,))
    require(set(doc) in ({"schema", "environment", "product",
                          "oracle"},
                         {"schema", "environment", "product",
                          "oracle", "sources"}),
            "gate inputs have invalid fields")
    require(doc["environment"] in ("offline", "ordinary-linux",
                                   "snp", "tdx", "hyperv"),
            "unknown gate environment")
    for side in ("product", "oracle"):
        require(isinstance(doc[side], dict) and doc[side],
                side + " measurements are empty")
        for value in doc[side].values():
            parse_size(value)
    sources = doc.get("sources")
    if sources is not None:
        exact(sources, {"product", "oracle"},
              "retained measurement sources")
        for side in ("product", "oracle"):
            require(isinstance(sources[side], dict),
                    side + " source bindings are invalid")
            for binding in sources[side].values():
                exact(binding, {"file", "sha256", "path",
                                "encoding"},
                      "measurement source binding")
                relative(binding["file"])
                hexid(binding["sha256"])
                require(isinstance(binding["path"], list)
                        and len(binding["path"]) <= 64,
                        "invalid measurement path")
                require(binding["encoding"] in ("boolean",
                                                "u64"),
                        "unknown measurement encoding")
    return "gate"


def derive_signer_pub(key_path):
    """Ed25519 public key for a signing key via ssh-keygen -y."""
    try:
        derived = subprocess.run(
            ["ssh-keygen", "-y", "-f", str(key_path)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as error:
        raise ValueError(
            "cannot read signing key: %s" % error) from error
    require(derived.returncode == 0,
            "cannot read signing key")
    try:
        key = derived.stdout.decode().strip()
    except UnicodeError as error:
        raise ValueError(
            "unsupported signing key") from error
    require(key.startswith("ssh-ed25519 ")
            and "\n" not in key, "unsupported signing key")
    return (key + "\n").encode()


def write_gate_receipt(gate, candidate_path, inputs_path,
                       key_path, out_path):
    """Author one signed gate receipt over retained inputs.

    Binds the versioned gate ID, the candidate file digest and
    source commit, and the inputs digest; the recorded inputs
    name is the basename of the given inputs file, which must
    be a clean evidence-relative name. Matrix gates require
    matrix inputs and every other gate requires gate inputs.
    Writes the canonical receipt to out_path (refusing to
    overwrite), its ssh-keygen -Y signature next to it, and
    stages the derived signer key as signer.pub beside the
    receipt: an existing staged key must equal the signing
    key, so one evidence directory keeps one qualifier key.
    Self-verifies the triple, prints nothing, and returns the
    receipt digest hex. A failed run leaves no partial files
    behind and never deletes a pre-existing staged key.
    """
    require(isinstance(gate, str)
            and re.fullmatch(GATE_ID_RE, gate),
            "gate IDs must be versioned")
    manifest = load_manifest(candidate_path)
    candidate_id = digest(candidate_path)
    inputs_bytes = read_regular(inputs_path)
    kind = validate_inputs_doc(_parse_json(inputs_bytes))
    require((gate == MATRIX_GATE) == (kind == "matrix"),
            "gate inputs schema mismatches the gate")
    pub = derive_signer_pub(key_path)
    record = {"schema": GATE_RECEIPT_SCHEMA, "gate": gate,
              "candidate_sha256": candidate_id,
              "source_commit":
              manifest["source"]["commit"],
              "inputs": relative(Path(inputs_path).name),
              "inputs_sha256":
              digest_bytes(inputs_bytes)}
    out = Path(out_path)
    signature = Path(str(out) + ".sig")
    require(not os.path.lexists(signature),
            "refusing to overwrite " + signature.name)
    created = []
    done = False
    try:
        write_once(out, canonical(record))
        created.append(out)
        try:
            signed = subprocess.run(
                ["ssh-keygen", "-Y", "sign", "-f",
                 str(key_path), "-n", SIGNING_NAMESPACE,
                 str(out)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
        except OSError as error:
            raise ValueError(
                "gate receipt signing failed: %s"
                % error) from error
        require(signed.returncode == 0,
                "gate receipt signing failed")
        created.append(signature)
        staged = out.parent / "signer.pub"
        if os.path.lexists(staged):
            require(staged.read_bytes() == pub,
                    "evidence signer differs from the "
                    "signing key")
        else:
            write_once(staged, pub)
            created.append(staged)
        verify_signature(out, signature, staged,
                         [digest(staged)])
        done = True
    finally:
        if not done:
            for path in created:
                try:
                    os.unlink(path)
                except OSError:
                    pass
            try:
                os.unlink(signature)
            except OSError:
                pass
    return digest_bytes(canonical(record))


def write_qualification(manifest_path, policy_path, gate_paths,
                        evidence_dir, out_path):
    """Assemble a qualification from verified gate receipts.

    Every receipt must be sealed inside the evidence
    directory, honestly signed by the policy trust staged as
    evidence signer.pub, bound to the sealed candidate and
    source, and digest-bound to its retained inputs bytes;
    non-matrix gates additionally re-derive their retained
    measurements against the policy, and the matrix gate
    re-derives its evidence inventory. The receipt set must
    equal the policy's required gates exactly: unknown,
    missing, or duplicate gates refuse. Matrix row predicates
    are not re-derived here (they need the source lock at C);
    qualify owns them. Refuses before the first write when
    either output path already exists, so a failed re-run
    never orphans a previous run's outputs. On success packs
    the evidence once, writes the archive beside the
    qualification under the required evidence name, and
    writes the sealed qualification binding its real digest
    and size, so the digest can never describe bytes packed
    later. Returns the qualification digest hex.
    """
    require(gate_paths, "no gate receipts")
    manifest = load_manifest(manifest_path)
    candidate_id = digest(manifest_path)
    validated, policy_digest = validate_policy(policy_path)
    require(policy_digest == manifest["policy_sha256"],
            "policy differs from candidate")
    base = Path(evidence_dir)
    require(base.is_dir() and not base.is_symlink(),
            "evidence directory is missing")
    root = base.resolve()
    bindings = {}
    for gate_path in gate_paths:
        receipt = Path(gate_path)
        try:
            rel = receipt.resolve().relative_to(root)
        except ValueError:
            rel = None
        require(rel is not None,
                "gate receipt is outside the evidence "
                "directory: " + str(gate_path))
        relname = relative(rel.as_posix())
        record = read_json(receipt, sealed=True)
        exact(record,
              {"schema", "gate", "candidate_sha256",
               "source_commit", "inputs", "inputs_sha256"},
              "signed gate receipt")
        require(record["schema"] == GATE_RECEIPT_SCHEMA,
                "unsupported gate receipt")
        ident = record["gate"]
        require(ident in validated["required_gates"],
                "gate receipt is outside the policy: "
                + str(ident))
        require(ident not in bindings,
                "duplicate gate receipt: " + str(ident))
        bindings[ident] = (relname, receipt, record)
    require(set(bindings)
            == set(validated["required_gates"]),
            "gate receipts differ from the policy")
    trusted = validated["trusted_keys"]
    public = base / "signer.pub"
    gates = {}
    for ident in sorted(bindings):
        relname, receipt, record = bindings[ident]
        verify_signature(receipt,
                         Path(str(receipt) + ".sig"),
                         public, trusted)
        require(record["candidate_sha256"] == candidate_id
                and record["source_commit"]
                == manifest["source"]["commit"],
                "gate subject mismatch")
        relative(record["inputs"])
        inputs = base / record["inputs"]
        require(digest(inputs)
                == hexid(record["inputs_sha256"]),
                "retained gate inputs changed")
        gates[ident] = {
            "receipt": relname,
            "receipt_sha256": digest(receipt),
            "signature": relname + ".sig",
            "public_key": "signer.pub"}
        retained = read_json(inputs, sealed=True)
        if ident == MATRIX_GATE:
            verify_evidence_inventory(retained, base)
        else:
            verify_measurement_sources(retained, base)
            rederive_measurements(
                retained,
                validated["required_gates"][ident])
            if ident == LIVE_GATE:
                verify_live_campaigns(retained, base,
                                      manifest)
    out = Path(out_path)
    try:
        nested = out.resolve().relative_to(root)
    except ValueError:
        nested = None
    require(nested is None,
            "qualification must live beside the evidence "
            "archive, never inside it")
    archive = out.parent / "qualification-evidence.tar.gz"
    # Refuse output collision before the first write: a
    # failed re-run must never orphan a previous run's
    # qualification or archive, so the failure-path unlink
    # below only removes an archive this run packed.
    require(not os.path.lexists(out),
            "refusing to overwrite " + out.name)
    require(not os.path.lexists(archive),
            "refusing to overwrite " + archive.name)
    build_evidence_archive(base, archive)
    doc = {"schema": QUALIFICATION_SCHEMA,
           "candidate_sha256": candidate_id,
           "source_commit": manifest["source"]["commit"],
           "claim": validated["claim"], "gates": gates,
           "evidence_archive": {
               "name": "qualification-evidence.tar.gz",
               "size": str(archive.stat().st_size),
               "sha256": digest(archive)}}
    try:
        write_once(out, canonical(doc))
    except OSError:
        try:
            os.unlink(archive)
        except OSError:
            pass
        raise
    return digest_bytes(canonical(doc))


def write_remote(import_path, check_paths, out_path):
    """Assemble remote custody from a verified import + checks.

    The import record must be the sealed local-build custody
    statement; each check file carries one import-run identity
    envelope plus one signed check binding. Every envelope
    must agree byte for byte, every receipt must bind the
    import's candidate and source, every inputs digest must
    match, every count predicate is re-derived, and every
    signature must verify over its receipt against its own
    staged key, which proves the record is internally
    consistent but not yet authorized: qualifier-key trust
    and the live check-run verification stay in promote,
    which re-verifies all of this against policy trust. The
    check set must equal the required remote checks exactly.
    Writes the sealed remote custody record binding the
    import-run identity, the custody statement file bytes
    digest (what promote re-hashes, not a re-canonicalized
    digest), and the verified checks. Returns the record
    digest hex.
    """
    require(check_paths, "no remote checks")
    custody = read_json(import_path, sealed=True)
    exact(custody, {"schema", "operation", "build_origin",
                    "repository", "release_id", "assets",
                    "candidate_sha256", "source_commit"},
          "candidate import record")
    require(custody["schema"] == IMPORT_SCHEMA
            and custody["operation"] == "import"
            and custody["build_origin"] == "local-build",
            "untrusted custody origin/subject")
    remote_repository(custody["repository"])
    remote_id(custody["release_id"])
    require(isinstance(custody["assets"], dict)
            and custody["assets"], "import assets are empty")
    for name, ident in custody["assets"].items():
        require("/" not in relative(name),
                "asset name must be a basename")
        remote_id(ident)
    candidate_id = hexid(custody["candidate_sha256"])
    source = hexid(custody["source_commit"], 40)
    envelopes = []
    bindings = {}
    for check_path in check_paths:
        doc = read_json(check_path, sealed=True)
        exact(doc, {"schema", "import_run", "check"},
              "remote check record")
        require(doc["schema"] == CHECK_FILE_SCHEMA,
                "unsupported remote check record")
        run = doc["import_run"]
        exact(run, {"repository_id", "run_id", "artifact_id",
                    "artifact_sha256", "signer_commit"},
              "import run identity")
        for key in ("repository_id", "run_id",
                    "artifact_id"):
            remote_id(run[key])
        hexid(run["artifact_sha256"])
        hexid(run["signer_commit"], 40)
        envelopes.append(run)
        binding = doc["check"]
        exact(binding, {"check_id", "run_id", "head_sha",
                        "receipt", "inputs",
                        "signature_base64", "public_key"},
              "remote check binding")
        remote_id(binding["check_id"])
        remote_id(binding["run_id"])
        hexid(binding["head_sha"], 40)
        require(isinstance(binding["signature_base64"], str)
                and isinstance(binding["public_key"], str),
                "remote check signature encoding is invalid")
        require(isinstance(binding["inputs"], dict),
                "remote check inputs must be an object")
        receipt = binding["receipt"]
        exact(receipt, {"schema", "gate", "candidate_sha256",
                        "source_commit", "inputs_sha256"},
              "remote gate receipt")
        require(receipt["schema"] == REMOTE_GATE_SCHEMA,
                "unsupported remote gate receipt")
        ident = receipt["gate"]
        require(ident in REMOTE_CHECKS,
                "unknown remote check: " + str(ident))
        require(ident not in bindings,
                "duplicate remote check: " + str(ident))
        require(receipt["candidate_sha256"] == candidate_id
                and receipt["source_commit"] == source,
                "remote receipt subject differs")
        bindings[ident] = binding
    require(set(bindings) == set(REMOTE_CHECKS),
            "remote checks differ from the required set")
    first = envelopes[0]
    for run in envelopes[1:]:
        require(run == first,
                "import run identity differs across check "
                "records")
    for ident in sorted(bindings):
        binding = bindings[ident]
        require(digest_bytes(canonical(binding["inputs"]))
                == hexid(binding["receipt"]["inputs_sha256"]),
                "remote oracle inputs differ")
        rederive_measurements(
            binding["inputs"],
            {"environment": "offline",
             "predicates": {REMOTE_CHECKS[ident]: "equal",
                            "failures": "zero"}})
        with tempfile.TemporaryDirectory(
                prefix="remote-receipt-") as tmp:
            tmp = Path(tmp)
            write_once(tmp / "receipt",
                       canonical(binding["receipt"]))
            write_once(tmp / "signature", base64.b64decode(
                binding["signature_base64"], validate=True))
            write_once(tmp / "public",
                       binding["public_key"].encode())
            verify_signature(tmp / "receipt",
                             tmp / "signature",
                             tmp / "public",
                             [digest(tmp / "public")])
    doc = {"schema": REMOTE_CUSTODY_SCHEMA,
           "candidate_sha256": candidate_id,
           "source_commit": source,
           "repository": custody["repository"],
           "repository_id": first["repository_id"],
           "run_id": first["run_id"],
           "artifact_id": first["artifact_id"],
           "artifact_sha256": first["artifact_sha256"],
           "signer_commit": first["signer_commit"],
           "custody_sha256":
           digest(import_path),
           "checks": {ident: bindings[ident]
                      for ident in sorted(bindings)}}
    write_once(out_path, canonical(doc))
    return digest_bytes(canonical(doc))


def qualify_candidate(source, manifest_path, qualification_path,
                      policy_path, evidence_archive, output):
    """Qualify an evidence archive; export the tested payload.

    Requires HEAD evidence-only over C with no other worktree
    changes, verifies the sealed archive bytes, rederives every
    required signed gate over the extracted evidence plus the
    signed artifact checksums, then writes the expected payload
    once and returns it. Remote custody checks and the matrix
    lock binding at export belong to their own stages.
    """
    manifest = load_manifest(manifest_path)
    commit = git(source, "rev-parse", "HEAD")
    _verify_q_diff(source, manifest["source"]["commit"],
                   commit)
    changes = _git_paths(source, "diff", "--name-only",
                         "--no-renames", "-z", "HEAD")
    changes += _git_paths(source, "ls-files", "--others",
                          "--exclude-standard", "-z")
    for path in changes:
        require(evidence_only_path(path),
                "qualification source has non-evidence "
                "changes: " + path)
    doc = read_json(qualification_path, sealed=True)
    verify_file(evidence_archive, doc["evidence_archive"])
    with tempfile.TemporaryDirectory(
            prefix="candidate-qualify-") as tmp:
        evidence = safe_extract(evidence_archive,
                                Path(tmp) / "evidence", True,
                                False)
        qualified = verify_qualification(
            manifest_path, qualification_path, policy_path,
            evidence, source_tree=source)
        verify_signed_checksums(
            manifest, evidence, qualified["trusted_keys"])
    expected = expected_payload(manifest)
    write_once(output, "".join(
        value + "  " + name + "\n"
        for name, value in sorted(expected.items())).encode())
    return expected


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    seal = commands.add_parser(
        "seal", help="seal existing local outputs, without building")
    seal.add_argument("--bundle-dir", required=True)
    seal.add_argument("--artifacts-dir", required=True)
    seal.add_argument("--policy", required=True)
    seal.add_argument("--out", required=True)
    seal.add_argument("--source-root", default=".")
    seal.add_argument("--harness-bin", default=None)
    origin = commands.add_parser(
        "provenance",
        help="record truthful local origin of existing outputs")
    origin.add_argument("--bundle-dir", required=True)
    for role in ("bundle", "deb", "rpm", "source", "sbom"):
        origin.add_argument("--" + role, required=True)
    origin.add_argument("--out", required=True)
    origin.add_argument("--source-root", default=".")
    qualify = commands.add_parser(
        "qualify",
        help="rederive all required signed gates over evidence")
    qualify.add_argument("--manifest", required=True)
    qualify.add_argument("--qualification", required=True)
    qualify.add_argument("--policy", required=True)
    qualify.add_argument("--evidence-dir", required=True)
    qualify.add_argument("--source-tree", default=".",
                         help="source checkout carrying the "
                         "matrix lock at C")
    sign = commands.add_parser(
        "sign-checksums",
        help="hash staged artifacts and sign the checksums")
    sign.add_argument("--artifacts-dir", required=True)
    sign.add_argument("--key", required=True)
    sign.add_argument("--out-dir", required=True)
    pack = commands.add_parser(
        "pack-evidence",
        help="pack qualification evidence without "
        "local-only files")
    pack.add_argument("--evidence-dir", required=True)
    pack.add_argument("--out", required=True)
    receipt = commands.add_parser(
        "write-gate-receipt",
        help="author one signed gate receipt over retained "
        "inputs")
    receipt.add_argument("--gate", required=True)
    receipt.add_argument("--candidate", required=True)
    receipt.add_argument("--inputs", required=True)
    receipt.add_argument("--key", required=True)
    receipt.add_argument("--out", required=True)
    qualification = commands.add_parser(
        "write-qualification",
        help="assemble a qualification from verified gate "
        "receipts")
    qualification.add_argument("--manifest", required=True)
    qualification.add_argument("--policy", required=True)
    qualification.add_argument("--gates", nargs="+",
                               required=True)
    qualification.add_argument("--evidence-dir",
                               required=True)
    qualification.add_argument("--out", required=True)
    remote = commands.add_parser(
        "write-remote",
        help="assemble remote custody from a verified "
        "import plus check records")
    remote.add_argument("--import", dest="import_record",
                        required=True)
    remote.add_argument("--checks", nargs="+", required=True)
    remote.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "seal":
            manifest = create_manifest(
                args.bundle_dir, args.artifacts_dir, args.policy,
                {"root": args.source_root,
                 "harness_bin": args.harness_bin})
            print(seal_manifest(manifest, args.out))
        elif args.command == "qualify":
            qualified = verify_qualification(
                args.manifest, args.qualification,
                args.policy, args.evidence_dir,
                source_tree=args.source_tree)
            verify_signed_checksums(
                load_manifest(args.manifest),
                args.evidence_dir,
                qualified["trusted_keys"])
            print("all required signed qualification inputs "
                  "re-derived")
        elif args.command == "sign-checksums":
            print(sign_checksums(args.artifacts_dir, args.key,
                                 args.out_dir))
        elif args.command == "write-gate-receipt":
            print(write_gate_receipt(
                args.gate, args.candidate, args.inputs,
                args.key, args.out))
        elif args.command == "write-qualification":
            print(write_qualification(
                args.manifest, args.policy, args.gates,
                args.evidence_dir, args.out))
        elif args.command == "write-remote":
            print(write_remote(
                args.import_record, args.checks, args.out))
        elif args.command == "pack-evidence":
            excluded = build_evidence_archive(
                args.evidence_dir, args.out)
            print(digest(args.out))
            for member in excluded:
                print("excluded local-only: " + member,
                      file=sys.stderr)
        else:
            print(emit_provenance(
                args.bundle_dir,
                {"root": args.source_root, "bundle": args.bundle,
                 "deb": args.deb, "rpm": args.rpm,
                 "source": args.source, "sbom": args.sbom},
                args.out))
    except (OSError, ValueError, KeyError, StopIteration,
            subprocess.CalledProcessError, subprocess.TimeoutExpired,
            tarfile.TarError) as error:
        parser.exit(1, "candidate: " + str(error) + "\n")


if __name__ == "__main__":
    main()
