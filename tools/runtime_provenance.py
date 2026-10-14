#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Trace staged runtime files to pinned package bytes.

tools/package selects runtime libraries by NEEDED name from the
pixi environment. A filename match plus a fresh hash does not
prove those bytes came from the pinned packages: this module
fetches the locked ``.conda`` archives, verifies each against
``pixi.lock``, and compares staged bytes against archive members
with explicit relocation handling.

Contracts: the caller passes the sealed lock bytes (this
module never reads the lock from disk); ``conda-meta`` only
locates candidate owner archives, and ownership is proven by
archive membership; every staged runtime file must match its
archive member exactly, or match it through a declared conda
prefix relocation recorded in the manifest. Staged symlinks,
ambiguous owners, and unknown members fail closed. The
``zstd`` CLI decompresses archive streams (a packaging
prerequisite like patchelf). Verified archives parse from a
single hashed in-memory snapshot, never from a re-opened
cache path.

Standard library plus the ``zstd`` CLI only.
"""

import hashlib
import io
import json
import os
import posixpath
import re
import shutil
import subprocess
import tarfile
import tempfile
import threading
import urllib.request
import zipfile

FORMAT = "memveil-runtime-provenance"
VERSION = 1
CONDA_FORMAT_VERSION = 2
STAGED_LIBDIR = "lib"
FETCH_TIMEOUT = 120
FETCH_USER_AGENT = "MemVeil-runtime-provenance/1.0"
ARCHIVE_BYTES_CAP = 1024 * 1024 * 1024
MEMBER_BYTES_CAP = 512 * 1024 * 1024
LINK_HOPS_CAP = 8


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def split_conda_filename(filename):
    """(name, version, build) or None when the shape is wrong."""
    if not filename.endswith(".conda"):
        return None
    stem = filename[:-len(".conda")]
    parts = stem.rsplit("-", 2)
    if len(parts) != 3 or not parts[0] or not parts[1] \
            or not parts[2] or not parts[1][0].isdigit():
        return None
    return parts[0], parts[1], parts[2]


def read_lock_packages(lock_text):
    """Locked conda packages; ({filename: entry}, problems).

    Minimal strict reader for the pixi.lock subset packaging
    needs: top-level ``packages:`` entries of ``- conda: URL``
    with a ``sha256:`` line, and ``- url:`` channels declared
    before them. https URLs must sit under a locked channel;
    file URLs are permitted (bytes are still hash-verified).
    The caller passes the seal-checked bytes; the lock file
    itself is never read here, so a swap after sealing cannot
    change what is verified.
    """
    if not isinstance(lock_text, str):
        return {}, ["lock bytes are not text"]
    text = lock_text
    channels = []
    packages = {}
    problems = []
    seen_packages = False
    ended = False
    current = None

    def close_entry():
        if current is None:
            return
        if current.get("sha256") is None:
            problems.append("lock entry lacks sha256: %s"
                            % current["url"])
        elif current["filename"] in packages:
            problems.append("lock repeats package: %s"
                            % current["filename"])
        else:
            packages[current["filename"]] = current

    for raw in text.splitlines():
        line = raw.rstrip("\n")
        if line == "packages:":
            close_entry()
            current = None
            if seen_packages:
                problems.append(
                    "lock repeats its packages section")
                ended = True
                continue
            seen_packages = True
            continue
        if not seen_packages:
            stripped = line.strip()
            if stripped.startswith("- url:"):
                channels.append(stripped[len("- url:"):].strip())
            continue
        if ended:
            continue
        if line and not line[0].isspace() \
                and not line.startswith("- conda:"):
            close_entry()
            current = None
            ended = True
            continue
        if line.startswith("- conda:"):
            close_entry()
            url = line[len("- conda:"):].strip()
            filename = url.rsplit("/", 1)[-1]
            split = split_conda_filename(filename)
            if split is None:
                problems.append("lock has a bad package name: %s"
                                % url)
                current = None
                continue
            if url.startswith("https://"):
                if not any(url.startswith(channel)
                           for channel in channels):
                    problems.append(
                        "lock package outside locked channels: %s"
                        % url)
                    current = None
                    continue
            elif not url.startswith("file://"):
                problems.append(
                    "lock package uses an unsupported scheme: %s"
                    % url)
                current = None
                continue
            name, version, build = split
            current = {"filename": filename, "url": url,
                       "sha256": None, "name": name,
                       "version": version, "build": build}
            continue
        if current is not None and line.startswith("  sha256:"):
            digest = line[len("  sha256:"):].strip()
            if len(digest) != 64 or any(
                    ch not in "0123456789abcdef" for ch in digest):
                problems.append(
                    "lock has a bad sha256 for %s" % current["url"])
                current = None
                continue
            current["sha256"] = digest
            continue
    close_entry()
    if not seen_packages:
        problems.append("lock has no packages section")
    if problems:
        return {}, problems
    return packages, []


def ensure_archive(cache_dir, filename, url, sha256):
    """Verified archive path in the cache; (path, problems).

    A cached copy is re-hashed on every call; otherwise the
    archive downloads to a private temporary file, verifies,
    and moves into place atomically. The temporary file and
    any stale download residue are removed on every failure,
    and a non-regular residue fails closed instead of being
    opened through.
    """
    if os.path.basename(filename) != filename \
            or not filename.endswith(".conda"):
        return None, ["refusing to cache %r" % filename]
    try:
        os.makedirs(cache_dir, exist_ok=True)
    except OSError as exc:
        return None, ["archive cache unwritable: %s" % exc]
    kept = os.path.join(cache_dir, filename)
    if os.path.isfile(kept) and not os.path.islink(kept) \
            and sha256_file(kept) == sha256:
        return kept, []
    part = kept + ".part"
    if os.path.lexists(part):
        if os.path.islink(part) or not os.path.isfile(part):
            return None, ["refusing suspicious download "
                          "residue: %s" % (filename + ".part")]
        try:
            os.remove(part)
        except OSError as exc:
            return None, ["cannot clear download residue %s: %s"
                          % (filename, exc)]
    temp = None
    fd = None
    try:
        try:
            fd, temp = tempfile.mkstemp(
                dir=cache_dir, prefix=filename + ".",
                suffix=".download")
        except OSError as exc:
            return None, ["archive cache unwritable: %s" % exc]
        # An explicit agent: some hosts refuse urllib's default.
        request = urllib.request.Request(
            url, headers={"User-Agent": FETCH_USER_AGENT})
        try:
            with urllib.request.urlopen(
                    request,
                    timeout=FETCH_TIMEOUT) as response, \
                    os.fdopen(fd, "wb") as handle:
                fd = None
                total = 0
                while True:
                    chunk = response.read(1048576)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > ARCHIVE_BYTES_CAP:
                        raise ValueError(
                            "archive exceeds size cap")
                    handle.write(chunk)
        except (OSError, ValueError) as exc:
            return None, ["cannot fetch %s: %s" % (filename, exc)]
        if sha256_file(temp) != sha256:
            return None, ["%s sha256 mismatch; want %s"
                          % (filename, sha256)]
        try:
            os.replace(temp, kept)
        except OSError as exc:
            return None, ["cannot keep %s: %s" % (filename, exc)]
        temp = None
        return kept, []
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if temp is not None:
            try:
                os.remove(temp)
            except OSError:
                pass


def snapshot_archive(kept, sha256):
    """Verified archive bytes; (bytes, problem).

    The cache path is read exactly once and the bytes are
    re-hashed here, so every later parse step shares one
    verified snapshot instead of re-opening the path.
    """
    try:
        with open(kept, "rb") as handle:
            data = handle.read()
    except OSError as exc:
        return None, "archive unreadable: %s" % exc
    if len(data) > ARCHIVE_BYTES_CAP:
        return None, "archive exceeds size cap"
    if hashlib.sha256(data).hexdigest() != sha256:
        return None, "archive changed after verification"
    return data, None


def check_zstd(zstd="zstd"):
    """zstd CLI problems; [] means decompression is available."""
    if shutil.which(zstd) is None:
        return ["zstd is required to read runtime archives "
                "(apt install zstd)"]
    return []


def open_archive(data):
    """Validated .conda layout; (members, problems).

    data is one verified snapshot; members maps the payload
    role to its zip member name: {"pkg": ..., "info": ...}.
    """
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (OSError, zipfile.BadZipFile) as exc:
        return None, ["archive unreadable: %s" % exc]
    try:
        names = archive.namelist()
    except zipfile.BadZipFile as exc:
        return None, ["archive unreadable: %s" % exc]
    try:
        raw = archive.read("metadata.json")
    except (KeyError, zipfile.BadZipFile) as exc:
        return None, ["archive lacks readable metadata: %s" % exc]
    try:
        metadata = json.loads(raw.decode("utf-8"))
    except ValueError:
        return None, ["archive metadata is not JSON"]
    if metadata.get("conda_pkg_format_version") != \
            CONDA_FORMAT_VERSION:
        return None, ["archive has an unsupported format: %r"
                      % (metadata.get("conda_pkg_format_version"),)]
    pkg = [name for name in names
           if name.startswith("pkg-") and name.endswith(".tar.zst")]
    info = [name for name in names
            if name.startswith("info-") and name.endswith(".tar.zst")]
    if len(pkg) != 1 or len(info) != 1:
        return None, ["archive must hold exactly one payload "
                      "and one info stream"]
    if set(names) != {"metadata.json", pkg[0], info[0]}:
        return None, ["archive holds unexpected members"]
    return {"pkg": pkg[0], "info": info[0]}, []


def safe_tar_name(name):
    """True when a tar member name cannot escape its root."""
    if not name or name.startswith("/") or name.startswith("\\"):
        return False
    parts = name.replace("\\", "/").split("/")
    if any(part in ("", ".", "..") for part in parts):
        return False
    return True


def scan_tar(data, member, want=(), zstd="zstd"):
    """Map a zstd tar stream; (entries, blobs, problems).

    data is one verified snapshot; entries maps every member
    name to ("file", size) or ("link", target); blobs holds
    the bytes of wanted regular files. Every name is
    validated, duplicates refused, and reads capped; the
    child process always reaps.
    """
    problems = check_zstd(zstd)
    if problems:
        return None, None, problems
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        compressed = archive.read(member)
    except (OSError, KeyError, zipfile.BadZipFile) as exc:
        return None, None, ["archive stream unreadable: %s" % exc]
    try:
        proc = subprocess.Popen(
            [zstd, "-d", "-c", "-q"], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as exc:
        return None, None, ["cannot run zstd: %s" % exc]

    def feed():
        try:
            proc.stdin.write(compressed)
            proc.stdin.close()
        except (BrokenPipeError, OSError, ValueError):
            pass

    feeder = threading.Thread(target=feed, daemon=True)
    feeder.start()
    entries = {}
    blobs = {}
    want = set(want)
    try:
        with tarfile.open(fileobj=proc.stdout, mode="r|*") as tar:
            for info in tar:
                if not safe_tar_name(info.name):
                    return None, None, [
                        "tar member escapes its root: %r"
                        % info.name]
                if info.name in entries:
                    return None, None, [
                        "tar repeats member: %s" % info.name]
                if info.issym() or info.islnk():
                    entries[info.name] = ("link", info.linkname)
                    continue
                if not info.isfile():
                    entries[info.name] = ("other", "")
                    continue
                entries[info.name] = ("file", info.size)
                if info.name not in want:
                    continue
                reader = tar.extractfile(info)
                if reader is None:
                    return None, None, [
                        "tar member unreadable: %s" % info.name]
                chunks = []
                found = 0
                while True:
                    piece = reader.read(65536)
                    if not piece:
                        break
                    found += len(piece)
                    if found > MEMBER_BYTES_CAP:
                        return None, None, [
                            "tar member exceeds size cap: %s"
                            % info.name]
                    chunks.append(piece)
                blobs[info.name] = b"".join(chunks)
    except tarfile.TarError as exc:
        return None, None, ["tar stream unreadable: %s" % exc]
    finally:
        feeder.join(timeout=30)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    if proc.returncode != 0:
        return None, None, ["zstd failed, exit %d"
                            % proc.returncode]
    return entries, blobs, []


def apply_relocation(data, placeholder, prefix, file_mode):
    """Installed bytes from archived bytes; (bytes, problem).

    Text mode substitutes plainly and the placeholder must be
    present. Binary mode follows the installer c-string
    transform (conda binary_replace, rattler
    copy_and_replace_cstring_placeholder): each match of the
    placeholder through its NUL terminator replaces every
    occurrence inside it, keeps every other byte at its
    offset, and pads the total length reduction with zeros
    after the terminator, so the file length never changes.
    A prefix longer than the placeholder fails closed; a
    binary placeholder with no terminated occurrence
    installs the archived bytes verbatim.
    """
    if not placeholder:
        return None, "relocation lacks a placeholder"
    marked = placeholder.encode("utf-8")
    want = prefix.encode("utf-8")
    if file_mode == "text":
        if marked not in data:
            return None, "archived bytes lack the placeholder"
        return data.replace(marked, want), None
    if file_mode == "binary":
        pattern = re.compile(re.escape(marked) + rb"[^\0]*\0")
        fields = list(pattern.finditer(data))
        if not fields:
            return data, None
        for field in fields:
            span = field.group(0)
            count = span.count(marked)
            if (len(marked) - len(want)) * count < 0:
                return None, \
                    "install prefix exceeds placeholder width"

        def install(field):
            span = field.group(0)
            count = span.count(marked)
            padding = (len(marked) - len(want)) * count
            return span.replace(marked, want) + b"\0" * padding

        return pattern.sub(install, data), None
    return None, "unknown relocation mode: %r" % (file_mode,)


def resolve_env_chain(path, prefix):
    """(chain, final, problem) following env symlinks.

    chain lists prefix-relative posix paths from the link
    itself to the final target; every hop and its directory
    must stay inside the prefix and the target must be a
    regular file, so a hop through an outside directory
    fails even when the final target lands back inside.
    """
    base = os.path.realpath(prefix)
    chain = []
    current = path
    for _ in range(LINK_HOPS_CAP + 1):
        try:
            inside = os.path.realpath(current)
            parent = os.path.realpath(os.path.dirname(current))
        except OSError as exc:
            return None, None, "unresolvable path: %s" % exc
        if inside != base and not inside.startswith(base + os.sep):
            return None, None, \
                "path escapes the environment: %s" % path
        if parent != base and not parent.startswith(base + os.sep):
            return None, None, \
                "path escapes the environment: %s" % path
        try:
            link = os.path.islink(current)
        except OSError as exc:
            return None, None, "unresolvable path: %s" % exc
        chain.append(os.path.relpath(current, prefix).replace(
            os.sep, "/"))
        if not link:
            if not os.path.isfile(current):
                return None, None, \
                    "link target is not a file: %s" % path
            return chain, current, None
        try:
            target = os.readlink(current)
        except OSError as exc:
            return None, None, "unresolvable path: %s" % exc
        if not os.path.isabs(target):
            target = os.path.join(os.path.dirname(current), target)
        current = target
    return None, None, "symlink chain too deep: %s" % path


def resolve_archive_chain(members, start):
    """(chain, final, problem) following archive symlinks.

    members maps archive paths to ("file",) or ("link",
    target); absolute targets resolve from the archive root
    without escaping it.
    """
    chain = [start]
    current = start
    for _ in range(LINK_HOPS_CAP):
        entry = members.get(current)
        if entry is None:
            return None, None, \
                "archive lacks member: %s" % current
        if entry[0] == "file":
            return chain, current, None
        target = entry[1]
        if not target.startswith("/"):
            target = posixpath.normpath(posixpath.join(
                posixpath.dirname(current), target))
        else:
            target = posixpath.normpath(target.lstrip("/"))
        if target in ("", ".") or target.startswith("../") \
                or "/../" in target:
            return None, None, \
                "archive link escapes its root: %s" % current
        current = target
        chain.append(current)
    return None, None, "archive link chain too deep: %s" % start


def read_paths_doc(data, layout, zstd="zstd"):
    """Validated paths.json entries; ({path: entry}, problems)."""
    _, blobs, problems = scan_tar(
        data, layout["info"], want=("info/paths.json",),
        zstd=zstd)
    if problems:
        return None, problems
    raw = blobs.get("info/paths.json")
    if raw is None:
        return None, ["archive lacks info/paths.json"]
    try:
        doc = json.loads(raw.decode("utf-8"))
    except ValueError:
        return None, ["archive paths.json is not JSON"]
    if not isinstance(doc, dict) \
            or not isinstance(doc.get("paths"), list):
        return None, ["archive paths.json has the wrong shape"]
    entries = {}
    for entry in doc["paths"]:
        if not isinstance(entry, dict) \
                or not isinstance(entry.get("_path"), str) \
                or not isinstance(entry.get("sha256"), str):
            return None, ["archive paths.json has a bad entry"]
        if entry["_path"] in entries:
            return None, ["archive paths.json repeats %s"
                          % entry["_path"]]
        entries[entry["_path"]] = entry
    return entries, []


def verify_runtime_file(name, staged_path, env_path, owner,
                        packages, prefix, cache_dir, zstd="zstd"):
    """One staged runtime file; (problems, record|None)."""
    entry = packages.get(owner)
    if entry is None:
        return ["%s names an owner outside the lock: %s"
                % (name, owner)], None
    kept, problems = ensure_archive(
        cache_dir, owner, entry["url"], entry["sha256"])
    if problems:
        return ["%s: %s" % (name, problems[0])], None
    data, problem = snapshot_archive(kept, entry["sha256"])
    if problem is not None:
        return ["%s: %s" % (name, problem)], None
    layout, problems = open_archive(data)
    if problems:
        return ["%s: %s" % (name, problems[0])], None
    paths, problems = read_paths_doc(data, layout, zstd=zstd)
    if problems:
        return ["%s: %s" % (name, problems[0])], None
    env_chain, _, problem = resolve_env_chain(env_path, prefix)
    if problem is not None:
        return ["%s: %s" % (name, problem)], None
    members, _, problems = scan_tar(
        data, layout["pkg"], zstd=zstd)
    if problems:
        return ["%s: %s" % (name, problems[0])], None
    start = env_chain[0]
    archive_chain, final, problem = resolve_archive_chain(
        members, start)
    if problem is not None:
        return ["%s: %s" % (name, problem)], None
    recorded = paths.get(final)
    if recorded is None:
        return ["%s: archive has no record for %s" % (name, final)], \
        None
    if start != final:
        link_record = paths.get(start)
        if link_record is None or link_record.get("sha256") != \
                recorded["sha256"]:
            return ["%s: archive link record disagrees for %s"
                    % (name, start)], None
    if not os.path.isfile(staged_path) \
            or os.path.islink(staged_path):
        return ["%s: staged file is not a regular file" % name], \
        None
    _, blobs, problems = scan_tar(
        data, layout["pkg"], want=(final,), zstd=zstd)
    if problems:
        return ["%s: %s" % (name, problems[0])], None
    member_bytes = blobs.get(final)
    if member_bytes is None:
        return ["%s: archive member unreadable: %s" % (name, final)], \
        None
    member_sha = hashlib.sha256(member_bytes).hexdigest()
    if member_sha != recorded["sha256"] \
            or len(member_bytes) != recorded.get(
                "size_in_bytes", len(member_bytes)):
        return ["%s: archive member disagrees with its record: %s"
                % (name, final)], None
    if recorded.get("prefix_placeholder") is not None:
        relocated, problem = apply_relocation(
            member_bytes, recorded["prefix_placeholder"], prefix,
            recorded.get("file_mode"))
        if problem is not None:
            return ["%s: %s" % (name, problem)], None
        relocation = {
            "placeholder": recorded["prefix_placeholder"],
            "prefix": prefix,
            "file_mode": recorded.get("file_mode"),
        }
    else:
        relocated, relocation = member_bytes, None
    try:
        with open(staged_path, "rb") as handle:
            staged_bytes = handle.read()
    except OSError as exc:
        return ["%s: staged file unreadable: %s" % (name, exc)], \
        None
    staged_sha = hashlib.sha256(staged_bytes).hexdigest()
    if staged_bytes != relocated:
        return ["%s: staged bytes differ from %s %s"
                % (name, owner, final)], None
    symlink = None
    if len(env_chain) > 1 or len(archive_chain) > 1:
        symlink = {"env": env_chain, "archive": archive_chain}
    return [], {
        "package": entry["name"],
        "version": entry["version"],
        "build": entry["build"],
        "archive": owner,
        "archive_sha256": entry["sha256"],
        "member": final,
        "member_sha256": recorded["sha256"],
        "staged": "%s/%s" % (STAGED_LIBDIR, name),
        "staged_sha256": staged_sha,
        "relocation": relocation,
        "symlink": symlink,
    }


def verify_closure(staged, sources, owners, lock_text, prefix,
                   cache_dir, zstd="zstd"):
    """Every staged runtime file; (problems, records).

    staged maps lib names to staged paths, sources maps them to
    environment paths, owners maps them to lock archive names.
    lock_text is the seal-checked lock bytes. records maps
    staged rels to provenance entries.
    """
    packages, problems = read_lock_packages(lock_text)
    if problems:
        return problems, {}
    problems = check_zstd(zstd)
    if problems:
        return problems, {}
    found = []
    records = {}
    for name in sorted(staged):
        if name not in sources or name not in owners:
            found.append("%s has no source or owner mapping" % name)
            continue
        item, record = verify_runtime_file(
            name, staged[name], sources[name], owners[name],
            packages, prefix, cache_dir, zstd=zstd)
        found.extend(item)
        if record is not None:
            records[record["staged"]] = record
    return found, records


def owners_from_conda_meta(env_dir, names):
    """Owner archive per lib name; (owners, problems).

    conda-meta only locates candidate archives; archive
    membership plus the lock proves ownership. Shared or
    missing files fail closed.
    """
    meta = os.path.join(env_dir, "conda-meta")
    try:
        listing = sorted(os.listdir(meta))
    except OSError as exc:
        return {}, ["conda-meta unreadable: %s" % exc]
    files = {}
    for leaf in listing:
        if not leaf.endswith(".json"):
            continue
        try:
            with open(os.path.join(meta, leaf), "r",
                      encoding="utf-8") as handle:
                record = json.load(handle)
        except (OSError, ValueError) as exc:
            return {}, ["conda-meta %s unreadable: %s"
                        % (leaf, exc)]
        if not isinstance(record, dict) \
                or not isinstance(record.get("fn"), str) \
                or not isinstance(record.get("files"), list):
            return {}, ["conda-meta %s has the wrong shape" % leaf]
        for rel in record["files"]:
            if not isinstance(rel, str):
                return {}, ["conda-meta %s has the wrong shape"
                            % leaf]
            files.setdefault(rel, []).append(record["fn"])
    owners = {}
    problems = []
    for name in sorted(names):
        claimants = files.get("%s/%s" % (STAGED_LIBDIR, name), [])
        if len(claimants) != 1:
            problems.append(
                "%s has %d conda owners, want exactly 1"
                % (name, len(claimants)))
            continue
        owners[name] = claimants[0]
    if problems:
        return {}, problems
    return owners, []


def archive_for_package(packages, name):
    """Lock archive filename for a package name; (filename, problem)."""
    matches = sorted(
        filename for filename, entry in packages.items()
        if entry["name"] == name)
    if len(matches) != 1:
        return None, "package %s has %d locked archives, want 1" \
            % (name, len(matches))
    return matches[0], None


def verify_packaged_runtime(names, staged_libdir, env_libdir,
                            lock_text, prefix, cache_dir,
                            license_table, zstd="zstd"):
    """Provenance for a packaged closure; (problems, records, texts).

    names excludes caller-owned files (the native bridge): every
    other staged runtime file must trace to pinned bytes, and
    every license_table row must match its archive member.
    lock_text is the seal-checked lock bytes.
    """
    packages, problems = read_lock_packages(lock_text)
    if problems:
        return problems, {}, {}
    problems = check_zstd(zstd)
    if problems:
        return problems, {}, {}
    owners, problems = owners_from_conda_meta(prefix, names)
    if problems:
        return problems, {}, {}
    found = []
    records = {}
    for name in sorted(names):
        item, record = verify_runtime_file(
            name, os.path.join(staged_libdir, name),
            os.path.join(env_libdir, name), owners[name],
            packages, prefix, cache_dir, zstd=zstd)
        found.extend(item)
        if record is not None:
            records[record["staged"]] = record
    resolved = []
    for staged_rel, pkg_name, which, member in license_table:
        filename, problem = archive_for_package(packages, pkg_name)
        if problem is not None:
            found.append("%s: %s" % (staged_rel, problem))
            continue
        resolved.append((staged_rel, filename, which, member))
    staged_root = os.path.dirname(staged_libdir)
    item, texts = verify_runtime_licenses(
        staged_root, resolved, lock_text, cache_dir, zstd=zstd)
    found.extend(item)
    return found, records, texts


def verify_runtime_licenses(staged_root, table, lock_text,
                            cache_dir, zstd="zstd"):
    """Staged texts against archive members; (problems, records).

    table rows are (staged_rel, owner_filename, which, member):
    which selects the payload ("pkg") or metadata ("info")
    stream of the verified owner archive. lock_text is the
    seal-checked lock bytes.
    """
    packages, problems = read_lock_packages(lock_text)
    if problems:
        return problems, {}
    problems = check_zstd(zstd)
    if problems:
        return problems, {}
    found = []
    records = {}
    for staged_rel, owner, which, member in table:
        entry = packages.get(owner)
        if entry is None:
            found.append("%s names an owner outside the lock: %s"
                         % (staged_rel, owner))
            continue
        if which not in ("pkg", "info"):
            found.append("%s selects an unknown stream: %s"
                         % (staged_rel, which))
            continue
        kept, item = ensure_archive(
            cache_dir, owner, entry["url"], entry["sha256"])
        if item:
            found.append("%s: %s" % (staged_rel, item[0]))
            continue
        data, problem = snapshot_archive(kept, entry["sha256"])
        if problem is not None:
            found.append("%s: %s" % (staged_rel, problem))
            continue
        layout, item = open_archive(data)
        if item:
            found.append("%s: %s" % (staged_rel, item[0]))
            continue
        full = os.path.join(staged_root, staged_rel)
        if not os.path.isfile(full) or os.path.islink(full):
            found.append("%s: staged file is not a regular file"
                         % staged_rel)
            continue
        _, blobs, item = scan_tar(
            data, layout[which], want=(member,), zstd=zstd)
        if item:
            found.append("%s: %s" % (staged_rel, item[0]))
            continue
        data = blobs.get(member)
        if data is None:
            found.append("%s: archive lacks member %s"
                         % (staged_rel, member))
            continue
        try:
            with open(full, "rb") as handle:
                staged_bytes = handle.read()
        except OSError as exc:
            found.append("%s: staged file unreadable: %s"
                         % (staged_rel, exc))
            continue
        if staged_bytes != data:
            found.append("%s: staged text differs from %s %s"
                         % (staged_rel, owner, member))
            continue
        records[staged_rel] = {
            "package": entry["name"],
            "member": member,
            "sha256": hashlib.sha256(data).hexdigest(),
        }
    return found, records
