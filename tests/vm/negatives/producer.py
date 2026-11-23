#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Test-only deterministic producer for negative copy objects.

Builds the four scenario negative objects
(`swiotlb_copy-<name>.bpf.o`) the kernel-matrix scenario mode
stages, as Rust-native Aya probes. Each object derives from the
pinned copy-probe source plus exactly one anchored source delta
(see README.md in this directory for the recovered specs and the
Aya re-expression). No live VMs, no boots, no privileged calls:
plain builds plus file writes under `build/bpf-negative/`.

Determinism: the producer verifies every probe input against its
pinned sha256 before copying, applies exact-once anchors, and
builds with the pinned nightly recipe from
`tests/vm/fixtures/aya/README.md` (same flags, same remaps; the
mutant trees live under the repository root so the checkout
remap covers them, and the cargo target dir is proven
non-leaking). Rebuilding twice in one checkout yields
identical bytes; across checkouts the loader-read sections
stay identical while DWARF varies (absolute-path-derived
crate disambiguators, recipe-inherent), so the manifest binds
both the full sha256 and the loader sha256 (see README.md).

Fail-closed: unknown input bytes, a missing anchor, a missing
toolchain, an unexpected occupant of an output path, or a dirty
pin all refuse with a naming message. Retired pre-cutover C
objects (known shas only) move aside to `<name>.retired-c.bpf.o`,
never silently overwritten.
"""

import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import elfutil

NAMES = ("renamed_field", "widened_layout",
         "wrong_shift", "wrong_argcnt")

NIGHTLY = "nightly-2026-05-20"
RUSTC_COMMIT = "e50aa6fba4e63ab34c72bf9acfd2c307c1155d1a"
BPF_LINKER_VERSION = "0.10.4"

# Pinned probe inputs: every file the copy object builds from,
# as committed for the qualified candidate (byte-identical in
# the candidate tree and this checkout).
PINNED_INPUTS = {
    "crates/ebpf/src/copy.rs":
        "6c7998afb28959dbfa6db59dabb049a96b7005bf91c24fb9"
        "057f70a765edcfdd",
    "crates/ebpf/src/common.rs":
        "0afe3e06394ce50099848b596776fbbcb412fa4f22ea6ef"
        "2f4dff9b1a427e62a",
    "crates/ebpf/src/bin/copy.rs":
        "ff66d753570934d2edc3f5610abfb085246d45a005f6a919"
        "9462e03a93914db1",
    "crates/ebpf/Cargo.toml":
        "0bac8479a9f8c3a0bcf214807a724619c0a10202a798cdd2"
        "cbf7d4d19841199d",
    "crates/ebpf/Cargo.lock":
        "73ce54d9a6a19029d8d6e2dc5242ea53e8054285d205b32b"
        "066ef8bb432f5ea8",
    "crates/ebpf/rust-toolchain.toml":
        "657c8d393a73b47d61d0cde44129f255f73fdc5d72d115830"
        "d7ecd1ca0f51c63",
    "crates/ebpf-common/src/lib.rs":
        "69f15fe6b112ef87a2a9ce85dd8719b88bb23ccde5cc378a"
        "bef020e8a3c4bd2b",
    "crates/ebpf-common/Cargo.toml":
        "e59200948711141d02dd44718c9e00bceee5cd3c7ffd22077"
        "5af9b70ba0d19e8",
    "tests/vm/fixtures/aya/README.md":
        "c432a36e51b34afebd5d82436d1ab68734f173910657d71b7"
        "3b53f75d80ba40e",
}

# Full sha256 of the committed baseline fixture
# (`tests/vm/fixtures/aya/swiotlb_copy.bpf.o`): the fixture
# tracks the sealed bytes (currently the 08bdeaed seal's
# copy object), and the reproduction control pins it to
# this digest. A fresh base rebuild is compared against the
# fixture's behavior bytes (see the test), not full bytes:
# full bytes move with the checkout path (codegen metadata)
# and with source lines (BTF line info), so byte-identity
# only binds staged copies of one build. (The previous value
# bound the superseded 39f4a227 seal's bytes; the candidate
# record below keeps that qualified history.)
BASELINE_COPY_SHA256 = (
    "daacd9950fec82d00c9dde5a33a7398d7e3c708d557455ab"
    "93b521aa0cf94227"
)

# Full candidate manifest digest (sha256 of the qualified
# candidate's candidate.json, source commit 1af6cc9): the
# run-input manifest references this digest to bind the
# negative bytes to the candidate outside its sealed payload.
CANDIDATE_MANIFEST_SHA256 = (
    "ac2503a3ef4269826ae3f9512ca2402d45e767be2601c2893e"
    "812ebb6df929a7"
)
CANDIDATE_SOURCE_COMMIT = (
    "1af6cc9a912a38c8b2cb61da14749fbf1f628659"
)

# Retired pre-cutover C objects: the only occupants an output
# path may hold before a build (moved aside, never deleted).
RETIRED_C_SHA256 = {
    "renamed_field":
        "85fb73f630b980e8683f227b2ac32e25ea4e170eddd9b1eb9"
        "93c2b4c7728c909",
    "widened_layout":
        "a1b5f60e4da6378b5961a6ea71727fd4d09a6b9a06a9e572f"
        "1e9d0c7a407abb1",
    "wrong_argcnt":
        "e99db24466f7b92d07aa1aaa6ea7e4c7d1eaef0dbd59a97a2"
        "0e6f82e1e2d834d",
    "wrong_shift":
        "36d1ad9c983b8ee2a2e9f6b27efd6267058b06d26028face"
        "dabc9a2b827eef84",
}

MARKER = "NEGATIVE (test-only, deterministic)"


def repo_root():
    """Repository root above tests/vm/negatives."""
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(os.path.dirname(here))
    root = os.path.dirname(root)
    if not os.path.isfile(os.path.join(
            root, "crates", "ebpf", "Cargo.toml")):
        raise SystemExit("producer: cannot find repository "
                         "root above %s" % here)
    return root


def sha_file(path):
    """Sha256 hex of one file."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_pins(root):
    """Every pinned input matches; else name the drift."""
    bad = []
    for rel, want in sorted(PINNED_INPUTS.items()):
        path = os.path.join(root, rel)
        try:
            got = sha_file(path)
        except OSError as exc:
            bad.append("%s: unreadable (%s)" % (rel, exc))
            continue
        if got != want:
            bad.append("%s: sha %s, want %s"
                       % (rel, got[:16], want[:16]))
    if bad:
        raise SystemExit("producer: pinned inputs drifted:\n"
                         + "\n".join(bad))


def check_toolchain():
    """Pinned nightly plus linker present; return versions."""
    try:
        proc = subprocess.run(
            ["rustup", "run", NIGHTLY, "rustc",
             "--version", "--verbose"],
            capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SystemExit("producer: pinned nightly %s "
                         "unavailable: %s" % (NIGHTLY, exc))
    if proc.returncode != 0:
        raise SystemExit("producer: pinned nightly %s "
                         "refused: %s"
                         % (NIGHTLY, proc.stderr.strip()))
    commit = ""
    for line in proc.stdout.splitlines():
        if line.startswith("commit-hash:"):
            commit = line.split(":", 1)[1].strip()
    if commit != RUSTC_COMMIT:
        raise SystemExit("producer: nightly %s is commit %s, "
                         "want %s"
                         % (NIGHTLY, commit, RUSTC_COMMIT))
    linker = shutil.which("bpf-linker")
    if linker is None:
        raise SystemExit("producer: bpf-linker not on PATH")
    try:
        proc = subprocess.run(
            ["bpf-linker", "--version"],
            capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SystemExit("producer: bpf-linker failed: %s"
                         % exc)
    if BPF_LINKER_VERSION not in proc.stdout:
        raise SystemExit("producer: bpf-linker %s, want %s"
                         % (proc.stdout.strip(),
                            BPF_LINKER_VERSION))
    return {"nightly": NIGHTLY, "rustc_commit": commit,
            "bpf_linker": BPF_LINKER_VERSION}


def _once(text, anchor, name):
    """Anchor occurs exactly once; else fail closed."""
    if text.count(anchor) != 1:
        raise SystemExit("producer: %s anchor %r matches %d "
                         "times, want 1"
                         % (name, anchor[:48],
                            text.count(anchor)))
    return text.replace(anchor, "@@PATCH@@", 1)


def mutate_renamed(text):
    """Rename the pool nslabs binding; read it directly.

    Mirrors the C `#define nslabs mvt_nslabs` textually, then
    re-expresses the defect for Aya (which emits no field
    relocations): the renamed field matches no trusted table
    entry, so the probe reads it through a direct kernel
    dereference the verifier rejects at load. The host-side
    table slots stay untouched.
    """
    renamed, count = re.subn(r"\bnslabs\b", "mvt_nslabs",
                             text)
    if count != 8:
        raise SystemExit("producer: renamed_field renames %d "
                         "bindings, want 8" % count)
    for slot in ("pool_nslabs_off", "pool_nslabs_size"):
        if slot not in renamed:
            raise SystemExit("producer: renamed_field lost "
                             "table slot %s" % slot)
    anchor = ("    let Ok(mvt_nslabs) = kread_u64(pool.wrapping_add("
              "u64::from(tab.pool_nslabs_off))) else {\n"
              "        return MV_CP_REASON_SLOT_READ;\n"
              "    };")
    patched = _once(renamed, anchor, "renamed_field")
    return patched.replace(
        "@@PATCH@@",
        "    // %s: the pool field is renamed\n"
        "    // (mvt_nslabs), so it matches no trusted table\n"
        "    // entry; the direct kernel read below is rejected\n"
        "    // by the verifier at load, while the base\n"
        "    // helper-path object loads.\n"
        "    let mvt_nslabs =\n"
        "        unsafe { (pool.wrapping_add(u64::from("
        "tab.pool_nslabs_off)) as *const u64).read() };"
        % MARKER, 1)


def mutate_layout(text):
    """Compare the mask width against 8, not 4."""
    anchor = "|| tab.mask_size != 4"
    patched = _once(text, anchor, "widened_layout")
    return patched.replace(
        "@@PATCH@@",
        "|| tab.mask_size != 8 // %s: widened local width;\n"
        "    // copies stay unknown with reason LAYOUT"
        % MARKER, 1)


def mutate_shift(text):
    """Double the slot count into the span check."""
    anchor = ("let idx = match slot_index(start, end, "
              "nslabs, tlb_addr) {")
    patched = _once(text, anchor, "wrong_shift")
    return patched.replace(
        "@@PATCH@@",
        "// %s: doubled slot count; the span guard\n"
        "    // returns SHIFT, geometry never matches.\n"
        "    let idx = match slot_index(start, end, "
        "nslabs.wrapping_mul(2), tlb_addr) {" % MARKER, 1)


def mutate_argcnt(text):
    """Expect 4 bounce arguments, not 5 (sync keeps 5)."""
    anchor = "const MV_ARGS_BOUNCE: i64 = 5;"
    patched = _once(text, anchor, "wrong_argcnt")
    return patched.replace(
        "@@PATCH@@",
        "// %s: wrong hook arity; bounce hooks stay out.\n"
        "const MV_ARGS_BOUNCE: i64 = 4;" % MARKER, 1)


MUTATIONS = {
    "renamed_field": mutate_renamed,
    "widened_layout": mutate_layout,
    "wrong_shift": mutate_shift,
    "wrong_argcnt": mutate_argcnt,
}


def stage_tree(root, name, dest_name=None):
    """Copy the verified probe crates; apply one mutation.

    Returns the mutant copy.rs sha256.
    """
    neg = os.path.join(root, "build", "bpf-negative")
    dest = os.path.join(neg, "src", dest_name or name)
    if os.path.isdir(dest):
        shutil.rmtree(dest)
    os.makedirs(dest)
    for crate in ("ebpf", "ebpf-common"):
        shutil.copytree(os.path.join(root, "crates", crate),
                        os.path.join(dest, crate),
                        symlinks=False)
    path = os.path.join(dest, "ebpf", "src", "copy.rs")
    with open(path, "r", encoding="utf-8") as handle:
        text = handle.read()
    mutated = MUTATIONS[name](text)
    if MARKER not in mutated:
        raise SystemExit("producer: %s lost its marker" % name)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(mutated)
    return sha_file(path)


def _cargo_build_copy(root, manifest, tmp, label):
    """Run the pinned recipe; return the built copy object."""
    sep = "\037"
    rustflags = sep.join([
        "-C", "linker=bpf-linker",
        "-C", "debuginfo=2",
        "-C", "link-arg=--btf",
        "-C", "target-cpu=v3",
        "--remap-path-prefix=%s=/build-prefix"
        % os.path.expanduser("~"),
        "--remap-path-prefix=%s=/build-root" % root,
    ])
    env = dict(os.environ)
    for knob in ("RUSTUP_TOOLCHAIN", "RUSTC",
                 "RUSTC_WORKSPACE_WRAPPER", "RUSTC_WRAPPER"):
        env.pop(knob, None)
    env["CARGO_ENCODED_RUSTFLAGS"] = rustflags
    proc = subprocess.run(
        ["rustup", "run", NIGHTLY, "cargo", "build",
         "--locked", "--release",
         "--target", "bpfel-unknown-none",
         "-Z", "build-std=core",
         "--manifest-path", manifest,
         "--target-dir", tmp],
        capture_output=True, text=True, timeout=1200,
        cwd=root, env=env)
    if proc.returncode != 0:
        raise SystemExit("producer: %s build failed:\n%s"
                         % (label, proc.stderr[-4000:]))
    built = os.path.join(tmp, "bpfel-unknown-none", "release",
                         "memveil-ebpf-copy")
    if not os.path.isfile(built):
        raise SystemExit("producer: %s built no copy object"
                         % label)
    return built


def build_staged(root, staged, outpath, retired_name=None):
    """Build one staged tree with the pinned recipe.

    Flags mirror tests/vm/fixtures/aya/README.md exactly; the
    target dir is a fresh temporary directory (proven not to
    leak into the bytes). An existing output must either match
    the fresh bytes or (for canonical names only) hold the
    known retired C bytes, which move aside. Returns the
    object sha256.
    """
    manifest = os.path.join(root, "build", "bpf-negative",
                            "src", staged, "ebpf", "Cargo.toml")
    tmp = tempfile.mkdtemp(prefix="neg-target-")
    try:
        built = _cargo_build_copy(root, manifest, tmp, staged)
        if os.path.isfile(outpath):
            occupant = sha_file(outpath)
            if occupant == sha_file(built):
                return occupant
            if retired_name is None or occupant != \
                    RETIRED_C_SHA256[retired_name]:
                raise SystemExit(
                    "producer: %s holds unknown bytes %s; "
                    "refusing to overwrite"
                    % (outpath, occupant))
            aside = os.path.join(
                root, "build", "bpf-negative",
                "swiotlb_copy-%s.retired-c.bpf.o"
                % retired_name)
            os.rename(outpath, aside)
        shutil.copy2(built, outpath)
        return sha_file(outpath)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def build_object(root, name):
    """Build one mutant to its canonical output; its sha256."""
    return build_staged(
        root, name,
        os.path.join(root, "build", "bpf-negative",
                     "swiotlb_copy-%s.bpf.o" % name),
        retired_name=name)


def build_base_object(root, outpath):
    """Rebuild the unmutated probe to outpath; its sha256.

    Builds the pinned tree in place (read-only: cargo writes
    only to a fresh temporary target dir). The bytes are not
    expected to equal the baseline fixture exactly: full
    bytes move with checkout-derived codegen metadata and
    BTF line info moves with source lines. Callers compare
    behavior against the fixture instead (identical behavior
    sections plus an identical loader-parse judgment, with
    the fixture itself pinned to BASELINE_COPY_SHA256): the
    positive control for the recipe itself.
    """
    check_pins(root)
    check_toolchain()
    tmp = tempfile.mkdtemp(prefix="neg-target-")
    try:
        built = _cargo_build_copy(
            root,
            os.path.join(root, "crates", "ebpf", "Cargo.toml"),
            tmp, "base")
        shutil.copy2(built, outpath)
        return sha_file(outpath)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def loader_sha256_of(path):
    """Loader-relevant sha256: every section but DWARF.

    Hashes the sorted (name, bytes) pairs for all sections
    except the `.debug*` family, which the loader never reads
    (it consumes BTF, not DWARF). DWARF embeds absolute-path-
    derived crate disambiguators, so full bytes vary across
    checkouts while this digest stays stable for the
    producer's fixed relative staging layout (BTF carries
    the remapped relative source paths).
    """
    sections = elfutil.elf_sections(path)
    digest = hashlib.sha256(b"MVLOADER1")
    for name in sorted(sections):
        if name.startswith(".debug"):
            continue
        if name.startswith(".rel.debug"):
            continue
        blob = sections[name]
        digest.update(name.encode("utf-8") + b"\0")
        digest.update(struct.pack("<Q", len(blob)))
        digest.update(blob)
    return digest.hexdigest()


def git_revision(root):
    """HEAD sha plus clean flag (unknown when not a checkout)."""
    try:
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True,
            text=True, timeout=60, cwd=root)
        status = subprocess.run(
            ["git", "status", "--porcelain"], capture_output=True,
            text=True, timeout=60, cwd=root)
    except (OSError, subprocess.TimeoutExpired):
        return "unknown", False
    if head.returncode != 0:
        return "unknown", False
    clean = (status.returncode == 0
             and status.stdout.strip() == "")
    return head.stdout.strip(), clean


def recipe_shas(root):
    """Shas of the recipe documents the build pins to."""
    return {
        "aya_readme": sha_file(os.path.join(
            root, "tests", "vm", "fixtures", "aya",
            "README.md")),
        "ebpf_cargo_lock": sha_file(os.path.join(
            root, "crates", "ebpf", "Cargo.lock")),
        "ebpf_toolchain": sha_file(os.path.join(
            root, "crates", "ebpf", "rust-toolchain.toml")),
    }


def producer_source_sha():
    """Sha over the producer, proof, and oracle sources."""
    here = os.path.dirname(os.path.abspath(__file__))
    digest = hashlib.sha256()
    for rel in ("producer.py", "proof.py", "elfutil.py",
                "README.md", "oracle/Cargo.toml",
                "oracle/Cargo.lock", "oracle/src/main.rs"):
        with open(os.path.join(here, rel), "rb") as handle:
            digest.update(handle.read())
    return digest.hexdigest()


def manifest_path():
    """Canonical run-input manifest path."""
    return os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "run-input-manifest.json")


def write_manifest(root, versions, shas, mutant_src, path=None):
    """Write the run-input manifest; return its path."""
    head, clean = git_revision(root)
    manifest = {
        "schema": "memveil-negative-run-input/1",
        "objects": {
            name: {
                "file": "swiotlb_copy-%s.bpf.o" % name,
                "sha256": shas[name],
                "loader_sha256": loader_sha256_of(
                    os.path.join(
                        root, "build", "bpf-negative",
                        "swiotlb_copy-%s.bpf.o" % name)),
                "mutant_source_sha256": mutant_src[name],
            } for name in NAMES
        },
        "producer": {
            "revision": head,
            "tree_clean": clean,
            "source_sha256": producer_source_sha(),
        },
        "pins": {
            "nightly": versions["nightly"],
            "rustc_commit": versions["rustc_commit"],
            "bpf_linker": versions["bpf_linker"],
            "aya_ebpf": "0.2.1",
            "aya_build": "0.2.0",
            "aya_obj_oracle": "0.3.0",
            "recipe": recipe_shas(root),
        },
        "baseline": {
            "copy_sha256": BASELINE_COPY_SHA256,
            "copy_source_sha256": PINNED_INPUTS[
                "crates/ebpf/src/copy.rs"],
        },
        "candidate": {
            "manifest_sha256": CANDIDATE_MANIFEST_SHA256,
            "source_commit": CANDIDATE_SOURCE_COMMIT,
        },
    }
    path = path or manifest_path()
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return path


def verify_manifest(root, path, for_fresh_rebuild=False):
    """Check a manifest against staged bytes and pins.

    Returns a list of problems (empty when it verifies):
    every name present with the staged sha256 and
    loader_sha256, pins current, baseline and candidate
    references exact. When for_fresh_rebuild is true, only
    the full-file sha256 is not compared: its DWARF sections
    embed checkout-derived codegen metadata, so full bytes
    are checkout-bound. loader_sha256 is still compared: it
    covers every section but DWARF and is cross-checkout
    stable for identical sources by construction -- the
    recipe remaps the home and checkout roots
    (--remap-path-prefix) and staged trees live under the
    checkout root. Fresh mode additionally compares the
    staged mutant SOURCES against mutant_source_sha256,
    with every other check unchanged. Staged copies of one
    build must verify with the default strict comparison,
    which also binds the full bytes.
    """
    try:
        with open(path, "r", encoding="utf-8") as handle:
            manifest = json.load(handle)
    except (OSError, ValueError) as exc:
        return ["unreadable manifest %s: %s" % (path, exc)]
    problems = []
    if manifest.get("schema") != "memveil-negative-run-input/1":
        problems.append("schema %r"
                        % manifest.get("schema"))
    objects = manifest.get("objects", {})
    for name in NAMES:
        entry = objects.get(name)
        if not isinstance(entry, dict):
            problems.append("%s: entry missing" % name)
            continue
        staged = os.path.join(
            root, "build", "bpf-negative",
            "swiotlb_copy-%s.bpf.o" % name)
        if entry.get("file") != \
                "swiotlb_copy-%s.bpf.o" % name:
            problems.append("%s: file %r"
                            % (name, entry.get("file")))
        try:
            staged_sha = sha_file(staged)
        except OSError:
            problems.append("%s: staged bytes missing" % name)
            continue
        if not for_fresh_rebuild:
            if entry.get("sha256") != staged_sha:
                problems.append(
                    "%s: manifest %.16s, staged %.16s"
                    % (name, entry.get("sha256"), staged_sha))
        try:
            staged_loader = loader_sha256_of(staged)
        except (OSError, ValueError) as exc:
            problems.append("%s: loader sha unreadable: %s"
                            % (name, exc))
            continue
        if entry.get("loader_sha256") != staged_loader:
            problems.append(
                "%s: loader manifest %.16s, staged %.16s"
                % (name, entry.get("loader_sha256"),
                   staged_loader))
        if for_fresh_rebuild:
            source = os.path.join(
                root, "build", "bpf-negative", "src", name,
                "ebpf", "src", "copy.rs")
            try:
                staged_src = sha_file(source)
            except OSError:
                problems.append("%s: staged sources missing"
                                % name)
            else:
                if entry.get("mutant_source_sha256") != \
                        staged_src:
                    problems.append(
                        "%s: source manifest %.16s, staged "
                        "%.16s"
                        % (name,
                           entry.get("mutant_source_sha256"),
                           staged_src))
    pins = manifest.get("pins", {})
    for key, want in (("nightly", NIGHTLY),
                      ("rustc_commit", RUSTC_COMMIT),
                      ("bpf_linker", BPF_LINKER_VERSION),
                      ("aya_ebpf", "0.2.1"),
                      ("aya_build", "0.2.0"),
                      ("aya_obj_oracle", "0.3.0")):
        if pins.get(key) != want:
            problems.append("pin %s: %r, want %r"
                            % (key, pins.get(key), want))
    try:
        want_recipe = recipe_shas(root)
    except OSError as exc:
        return problems + ["recipe unreadable: %s" % exc]
    if pins.get("recipe") != want_recipe:
        problems.append("recipe shas drifted")
    baseline = manifest.get("baseline", {})
    if baseline.get("copy_sha256") != BASELINE_COPY_SHA256:
        problems.append("baseline copy hash wrong")
    if baseline.get("copy_source_sha256") != PINNED_INPUTS[
            "crates/ebpf/src/copy.rs"]:
        problems.append("baseline copy source wrong")
    candidate = manifest.get("candidate", {})
    if candidate.get("manifest_sha256") != \
            CANDIDATE_MANIFEST_SHA256:
        problems.append("candidate manifest digest wrong")
    if candidate.get("source_commit") != \
            CANDIDATE_SOURCE_COMMIT:
        problems.append("candidate source commit wrong")
    return problems


def build_all(root, only=None):
    """Stage and build every (or one) negative; map shas."""
    check_pins(root)
    versions = check_toolchain()
    shas = {}
    mutant_src = {}
    for name in NAMES:
        if only is not None and name != only:
            continue
        mutant_src[name] = stage_tree(root, name)
        shas[name] = build_object(root, name)
        print("producer: %s %s" % (name, shas[name][:16]))
    return versions, shas, mutant_src


def main(argv):
    """Build negatives; write the run-input manifest."""
    root = repo_root()
    only = None
    args = list(argv)
    if "--name" in args:
        at = args.index("--name")
        try:
            only = args[at + 1]
        except IndexError:
            raise SystemExit("producer: --name needs a value")
        if only not in NAMES:
            raise SystemExit("producer: unknown name %s" % only)
    versions, shas, mutant_src = build_all(root, only)
    if only is None:
        path = write_manifest(root, versions, shas,
                              mutant_src)
        print("producer: manifest %s" % path)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
