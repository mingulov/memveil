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
and the engine/BPF output digests. `tools/candidate provenance`
composes the local-build provenance record from that recorded
receipt plus the re-hashed artifact subjects, never inventing
values. The seal requires the provenance receipt to equal the
recorded receipt and cross-checks the recorded bpf-linker against
the probed toolchain, so a prebuilt engine from another commit, or
one swapped after the receipt was recorded, fails closed.

Usage:
  tools/candidate seal --bundle-dir D --artifacts-dir A --policy P \\
      --out M [--source-root R] [--harness-bin H]
  tools/candidate provenance --bundle-dir D --bundle B --deb E \\
      --rpm R --source S --sbom J --out P [--source-root R]
Standard library only. Exit 0 prints the sealed digest; exit 1
reports the reason on stderr.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile

SCHEMA = "memveil-candidate/2"
PROVENANCE_SCHEMA = "memveil-local-build/2"
ORIGIN = "local-build"
ROLES = frozenset({"bundle", "deb", "rpm", "source", "sbom", "provenance"})
BPF_OBJECTS = ("swiotlb_attempt.bpf.o", "swiotlb_lifecycle.bpf.o",
               "swiotlb_copy.bpf.o")
DOCUMENT_LIMIT = 16 * 1024 * 1024
HARNESS_PACKAGE = "memveil-release-entry"


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


def read_json(path, sealed=False):
    data = read_regular(path)
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
    require(any(name.startswith("lib/memveil/")
                for name in doc["files"]),
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
    """`channel` value from the source root rust-toolchain.toml."""
    try:
        with open(os.path.join(str(root), "rust-toolchain.toml"),
                  encoding="utf-8") as handle:
            text = handle.read()
    except OSError as error:
        raise ValueError(
            "source lacks rust-toolchain.toml") from error
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip() == "channel":
            return value.strip().strip('"')
    raise ValueError("source toolchain pin has no channel")


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
    require(any(name.startswith("lib/memveil/") for name in files),
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
          {"source_commit", "inventory_sha256", "tools", "outputs"},
          "recorded build receipt")
    hexid(receipt["source_commit"], 40)
    hexid(receipt["inventory_sha256"])
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
    manifest_bytes = read_regular(manifest_path)
    return {"files": files, "manifest_bytes": manifest_bytes,
            "manifest_sha256": digest_bytes(manifest_bytes),
            "revision": revision, "lock_sha256": lock_sha,
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
    """({rel: sha256}, {rel: target}, {dirs}) under root, no follows."""
    files, links, dirs = {}, {}, set()
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
    return files, links, dirs


def verify_source_archive(path, entries):
    """Verify the source archive equals the git tree at C.

    Returns the archived Cargo lock digests. Every file must match
    by bytes, every symlink by target, with no missing or extra
    entries; modes come from git, never from tar extraction.
    """
    want_files = {entry["path"]: entry["sha256"]
                  for entry in entries if entry["kind"] == "file"}
    want_links = {entry["path"]: entry["target"]
                  for entry in entries if entry["kind"] == "symlink"}
    want_dirs = {entry["path"] for entry in entries
                 if entry["kind"] == "dir"}
    with tempfile.TemporaryDirectory(
            prefix="candidate-source-") as tmp:
        root = safe_extract(path, Path(tmp) / "source", False, True)
        files, links, dirs = walk_files(root)
    require(files == want_files, "source archive differs from C")
    require(links == want_links, "source archive differs from C")
    require(dirs == want_dirs, "source archive differs from C")
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
        files, links, _dirs = walk_files(root)
        require(not links, "bundle tarball carries symlinks")
        want, _, _ = walk_files(Path(bundle_dir))
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
          {"source_commit", "inventory_sha256", "tools", "outputs"},
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
    args = parser.parse_args(argv)
    try:
        if args.command == "seal":
            manifest = create_manifest(
                args.bundle_dir, args.artifacts_dir, args.policy,
                {"root": args.source_root,
                 "harness_bin": args.harness_bin})
            print(seal_manifest(manifest, args.out))
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
