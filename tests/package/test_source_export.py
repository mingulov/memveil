#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Source-export gate: HEAD exports cleanly and packages git-free.

Verifies the export mechanism against HEAD (required inputs
present, sealed file set, no generated paths), then proves a
standalone archive runs the provenance gate from its own tree:
outside any Git tree and under clean and dirty unrelated
parents (including a parent ignore rule naming our own
sources) the gate passes with one identical enumerated file
set, while a deleted required source/license file, an altered
profiles manifest, a stripped header on an ignored-but-
required source, a hostile Git environment, an unreadable
or misclassified source subtree, or a present-but-
unenumerated required input fails. Finally proves a
git-free export builds
and packages: tools/package runs inside the export with
LMB_PACKAGE pointed at the export's own vendored tarball, the
exported tree passes its own provenance gate as well, and the
resulting manifest records revision "export" with every
referenced manual shipped. Enforces the candidate rule: a
dirty worktree cannot produce a candidate export. Exits nonzero
while BLOCKED.
Standard library only.
"""

import hashlib
import os
import subprocess
import sys
import tarfile
import tempfile

ROOT = os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))

REQUIRED = (
    "pixi.toml",
    "pixi.lock",
    "toolchain.lock.json",
    "tools/build",
    "tools/test",
    "tools/package",
    "src/memveil/main.mojo",
    "bpf/programs/swiotlb_attempt.bpf.c",
    "bpf/include/memveil_events.h",
    "profiles/manifest.txt",
    "schemas/session-v0.1.1.schema.json",
    "README.md",
    "LICENSE",
)

GENERATED_MARKERS = (
    "/build/", "/dist/", "/.pixi/", "/__pycache__/",
    "/.pytest_cache/", "/.mypy_cache/",
)

# Probe: unreadable admitted paths must fail loudly, never
# silently shrink the archive inventory. Argv: tree. Exits 0
# only when a scandir EACCES, an lstat EACCES, a directory
# hidden by a classification failure, a suffix-renamed
# hidden directory, a combined classification plus probe
# failure, and the gate all fail loudly.
STRICT_PROBE = """\
import errno
import io
import os
import sys

tree = sys.argv[1]
sys.path.insert(0, os.path.join(tree, "tools"))
import source_inventory

base = {entry["path"] for entry in
        source_inventory.take_tree_inventory(tree)["files"]}
assert "src/memveil/main.mojo" in base, "setup: tree incomplete"
victim_dir = os.path.realpath(
    os.path.join(tree, "src", "memveil", "analysis"))
victim_file = os.path.join(
    tree, "src", "memveil", "main.mojo")
real_scandir = os.scandir
real_lstat = os.lstat


def hostile_scandir(path):
    if os.path.realpath(path) == victim_dir:
        raise PermissionError(errno.EACCES, "denied", path)
    return real_scandir(path)


def hostile_lstat(path):
    if os.path.abspath(path) == victim_file:
        raise PermissionError(errno.EACCES, "denied", path)
    return real_lstat(path)


os.scandir = hostile_scandir
try:
    source_inventory.take_tree_inventory(tree)
except OSError:
    pass
else:
    raise SystemExit("scandir EACCES silently omitted sources")
finally:
    os.scandir = real_scandir
os.lstat = hostile_lstat
try:
    source_inventory.take_tree_inventory(tree)
except OSError:
    pass
else:
    raise SystemExit("lstat EACCES silently omitted main.mojo")
finally:
    os.lstat = real_lstat
sys.path.insert(0, os.path.join(tree, "tests", "provenance"))
import test_provenance

os.scandir = hostile_scandir
old = sys.stdout
sys.stdout = io.StringIO()
try:
    code = test_provenance.main([])
except SystemExit as exc:
    code = exc.code
finally:
    out = sys.stdout.getvalue()
    sys.stdout = old
    os.scandir = real_scandir
assert code != 0, "gate passed over an unreadable subtree"
assert "tree inventory failed" in out, out[-500:]


class ClassifyEntry:
    def __init__(self, entry):
        self._entry = entry
        self.path = entry.path
        self.name = entry.name

    def is_dir(self, *args, **kwargs):
        if os.path.realpath(self.path) == victim_dir:
            raise PermissionError(
                errno.EACCES, "denied", self.path)
        return self._entry.is_dir(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._entry, name)


class ClassifyIter:
    def __init__(self, iterator):
        self._iterator = iterator

    def __iter__(self):
        return self

    def __next__(self):
        entry = next(self._iterator)
        if os.path.realpath(entry.path) == victim_dir:
            return ClassifyEntry(entry)
        return entry

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return self._iterator.__exit__(*args)

    def close(self):
        self._iterator.close()


def hostile_classify(path):
    return ClassifyIter(real_scandir(path))


def run_gate():
    old = sys.stdout
    sys.stdout = io.StringIO()
    try:
        code = test_provenance.main([])
    except SystemExit as exc:
        code = exc.code
    finally:
        out = sys.stdout.getvalue()
        sys.stdout = old
    return code, out


os.scandir = hostile_classify
try:
    source_inventory.take_tree_inventory(tree)
except OSError:
    pass
else:
    raise SystemExit(
        "classification EACCES silently omitted sources")
finally:
    os.scandir = real_scandir
os.scandir = hostile_classify
try:
    code, out = run_gate()
finally:
    os.scandir = real_scandir
assert code != 0, "gate passed over a misclassified dir"
assert "tree inventory failed" in out, out[-500:]
engine = os.path.join(
    tree, "src", "memveil", "analysis", "engine.mojo")
with open(engine) as handle:
    text = handle.read()
stripped = text.replace(
    "SPDX-License-Identifier:",
    "License-Identifier-Removed:")
assert stripped != text, "setup: header not found"
with open(engine, "w") as handle:
    handle.write(stripped)
code, out = run_gate()
assert code != 0, "setup: stripped header passed clean"
assert "FAIL spdx-coverage" in out, out[-500:]
assert "engine.mojo" in out, out[-500:]
os.scandir = hostile_classify
try:
    code, out = run_gate()
finally:
    os.scandir = real_scandir
assert code != 0, "stripped header passed when dir hidden"
victim_virtual = victim_dir + ".pyc"
real_stat = os.stat
real_open = open
import builtins


def to_real(path):
    if not isinstance(path, str):
        return path
    norm = os.path.normpath(path)
    if norm == victim_virtual or norm.startswith(
            victim_virtual + os.sep):
        return victim_dir + norm[len(victim_virtual):]
    return path


class RenamedEntry:
    def __init__(self, entry, deny):
        self._entry = entry
        self._deny = deny
        self.name = "analysis.pyc"
        self.path = victim_virtual

    def is_dir(self, *args, **kwargs):
        if self._deny:
            raise PermissionError(
                errno.EACCES, "denied", self.path)
        return self._entry.is_dir(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._entry, name)


class VirtualIter:
    def __init__(self, iterator, deny):
        self._iterator = iterator
        self._deny = deny

    def __iter__(self):
        return self

    def __next__(self):
        entry = next(self._iterator)
        if os.path.normpath(entry.path) == victim_dir:
            return RenamedEntry(entry, self._deny)
        return entry

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return self._iterator.__exit__(*args)

    def close(self):
        self._iterator.close()


def virtual_scandir(deny):
    def scan(path):
        norm = os.path.normpath(path)
        if norm == victim_virtual or norm.startswith(
                victim_virtual + os.sep):
            target = victim_dir + norm[len(
                victim_virtual):]
        else:
            target = path
        return VirtualIter(real_scandir(target), deny)
    return scan


def virtual_lstat(path, *args, **kwargs):
    return real_lstat(to_real(path), *args, **kwargs)


def virtual_stat(path, *args, **kwargs):
    return real_stat(to_real(path), *args, **kwargs)


def virtual_open(file, *args, **kwargs):
    if isinstance(file, str):
        file = to_real(file)
    return real_open(file, *args, **kwargs)


def run_list():
    old = sys.stdout
    sys.stdout = io.StringIO()
    try:
        code = test_provenance.main(["--list-files"])
    except SystemExit as exc:
        code = exc.code
    finally:
        out = sys.stdout.getvalue()
        sys.stdout = old
    return code, out


def virtual_on(deny):
    os.scandir = virtual_scandir(deny)
    os.lstat = virtual_lstat
    os.stat = virtual_stat
    builtins.open = virtual_open


def virtual_off():
    os.scandir = real_scandir
    os.lstat = real_lstat
    os.stat = real_stat
    builtins.open = real_open


virtual_on(False)
try:
    renamed = {entry["path"] for entry in
               source_inventory.take_tree_inventory(
                   tree)["files"]}
finally:
    virtual_off()
assert "src/memveil/analysis.pyc/engine.mojo" in renamed, \\
    "setup: renamed child missing"
virtual_on(False)
try:
    code, out = run_gate()
finally:
    virtual_off()
assert code != 0, "setup: renamed tree passed clean"
assert "FAIL spdx-coverage" in out, out[-500:]
assert "engine.mojo" in out, out[-500:]
virtual_on(False)
try:
    code, out = run_list()
finally:
    virtual_off()
assert code == 0, out[-500:]
assert "src/memveil/analysis.pyc/engine.mojo" in out, \\
    out[-500:]
virtual_on(True)
try:
    source_inventory.take_tree_inventory(tree)
except OSError:
    pass
else:
    raise SystemExit(
        "suffix dir misclassification silently omitted")
finally:
    virtual_off()
virtual_on(True)
try:
    source_inventory.take_inventory(tree)
except OSError:
    pass
else:
    raise SystemExit("suffix dir hid owned inputs silently")
finally:
    virtual_off()
virtual_on(True)
try:
    code, out = run_gate()
finally:
    virtual_off()
assert code != 0, "gate passed over a renamed hidden dir"
assert "tree inventory failed" in out, out[-500:]
virtual_on(True)
try:
    code, out = run_list()
finally:
    virtual_off()
assert code != 0, "list passed over a renamed hidden dir"


def hostile_probe_lstat(path, *args, **kwargs):
    if isinstance(path, str) and os.path.normpath(
            path) == victim_virtual:
        raise PermissionError(
            errno.EACCES, "denied", path)
    return virtual_lstat(path, *args, **kwargs)


def combined_on():
    virtual_on(True)
    os.lstat = hostile_probe_lstat


combined_on()
try:
    source_inventory.take_tree_inventory(tree)
except OSError:
    pass
else:
    raise SystemExit(
        "combined probe EACCES silently omitted")
finally:
    virtual_off()
combined_on()
try:
    source_inventory.take_inventory(tree)
except OSError:
    pass
else:
    raise SystemExit(
        "combined probe hid owned inputs silently")
finally:
    virtual_off()
combined_on()
try:
    code, out = run_gate()
finally:
    virtual_off()
assert code != 0, "gate passed over combined failure"
assert "tree inventory failed" in out, out[-500:]
combined_on()
try:
    code, out = run_list()
finally:
    virtual_off()
assert code != 0, "list passed over combined failure"
print("strict traversal: scandir, lstat, classify, suffix, probe loud")
"""

# Probe: a required input that exists on disk but is missing
# from the enumerated set must fail the named membership
# check. Argv: tree, omitted path, enumeration mode label.
# Exits 0 only on that exact failure.
OMITTED_PROBE = """\
import io
import os
import sys

tree, omit, mode = sys.argv[1], sys.argv[2], sys.argv[3]
sys.path.insert(0, os.path.join(tree, "tests", "provenance"))
import test_provenance

files, _ = test_provenance.enumerated_files()
assert omit in files, "setup: %s not enumerated" % omit
assert os.path.isfile(os.path.join(tree, omit)), \\
    "setup: %s must exist" % omit
stubbed = [name for name in files if name != omit]
test_provenance.enumerated_files = lambda: (stubbed, mode)
old = sys.stdout
sys.stdout = io.StringIO()
try:
    code = test_provenance.main([])
except SystemExit as exc:
    code = exc.code
finally:
    out = sys.stdout.getvalue()
    sys.stdout = old
assert code != 0, "gate passed with %s omitted" % omit
assert "FAIL inventory-required-present" in out, out[-500:]
print("omitted %s in %s mode fails the named check"
      % (omit, mode))
"""


def check(name, cond, detail=""):
    if not cond:
        print("FAIL %s %s" % (name, detail))
        sys.exit(1)
    print("ok %s" % name)


def export_head(dest):
    archive = subprocess.run(
        ["git", "archive", "HEAD"], cwd=ROOT,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if archive.returncode != 0:
        print("FAIL export-head: git archive failed")
        sys.exit(1)
    with tempfile.NamedTemporaryFile(suffix=".tar") as tmp:
        tmp.write(archive.stdout)
        tmp.flush()
        with tarfile.open(tmp.name) as tar:
            tar.extractall(dest)


def seal(tree):
    sealed = {}
    for base, _, files in os.walk(tree):
        for name in files:
            full = os.path.join(base, name)
            rel = os.path.relpath(full, tree)
            digest = hashlib.sha256()
            with open(full, "rb") as handle:
                for chunk in iter(lambda: handle.read(65536), b""):
                    digest.update(chunk)
            sealed[rel] = digest.hexdigest()
    return sealed


def run_provenance(tree, *args, env=None):
    return subprocess.run(
        ["python3", os.path.join(
            "tests", "provenance", "test_provenance.py")]
        + list(args),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, cwd=tree, timeout=300, env=env)


def show(proc):
    return (proc.stdout + proc.stderr)[-2000:]


def init_unrelated(path, ignore=()):
    subprocess.run(["git", "-C", path, "init", "-q"], check=True)
    if ignore:
        with open(os.path.join(path, ".gitignore"), "w") as handle:
            handle.write("".join(
                line + "\n" for line in ignore))
        subprocess.run(["git", "-C", path, "add", ".gitignore"],
                       check=True)
    subprocess.run(["git", "-C", path, "-c", "user.name=Test", "-c",
                    "user.email=test@example.invalid", "commit",
                    "-qm", "unrelated", "--allow-empty"], check=True)


def hostile_git_env(tree, foreign, excludes):
    """Environment spoofing ownership from a foreign repo.

    Repository, work tree, index, and ignore rules all
    point at attacker-controlled values: unsanitized, the
    gate inherits the foreign file set instead of the
    complete archive inventory.
    """
    env = dict(os.environ)
    env["GIT_DIR"] = os.path.join(foreign, ".git")
    env["GIT_WORK_TREE"] = tree
    env["GIT_INDEX_FILE"] = os.path.join(
        foreign, "no-such-index")
    env["GIT_CONFIG_COUNT"] = "1"
    env["GIT_CONFIG_KEY_0"] = "core.excludesFile"
    env["GIT_CONFIG_VALUE_0"] = excludes
    return env


def inventory_digest(tree):
    proc = subprocess.run(
        ["python3", "tools/source_inventory.py", "."],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, cwd=tree, timeout=300)
    check("archive-inventory-runs", proc.returncode == 0,
          proc.stderr[-1000:])
    import json as _json
    return _json.loads(proc.stdout or "{}").get("digest")


def archive_provenance_cases(export):
    """Standalone-archive provenance matrix, positives first.

    export extracts a pristine source tree into the given
    directory (the committed lane passes export_head; the
    parameter exists so the same matrix can run against any
    caller-supplied tree shape).
    """
    lists = {}
    with tempfile.TemporaryDirectory(
            prefix="mv-prov-bare-") as bare:
        export(bare)
        proc = run_provenance(bare)
        check("archive-provenance-outside-git",
              proc.returncode == 0, show(proc))
        listed = run_provenance(bare, "--list-files")
        check("archive-provenance-list-outside-git",
              listed.returncode == 0, show(listed))
        lists["outside-git"] = listed.stdout
    # A "clean" parent has its own tracked content committed
    # with nothing modified; the extraction itself merely sits
    # there, untracked (or ignored where noted).
    parents = (
        ("clean-parent", (), False),
        ("clean-parent-ignored",
         ("export/src/memveil/main.mojo",), False),
        ("dirty-parent-ignored",
         ("export/src/memveil/main.mojo",), True),
    )
    for label, ignore, dirty in parents:
        with tempfile.TemporaryDirectory(
                prefix="mv-prov-parent-") as parent:
            init_unrelated(parent, ignore)
            if dirty:
                with open(os.path.join(
                        parent, "unrelated-dirty.txt"), "w") as handle:
                    handle.write("dirty parent\n")
            third = os.path.join(parent, "export")
            os.mkdir(third)
            export(third)
            proc = run_provenance(third)
            check("archive-provenance-under-%s" % label,
                  proc.returncode == 0, show(proc))
            listed = run_provenance(third, "--list-files")
            check("archive-provenance-list-under-%s" % label,
                  listed.returncode == 0, show(listed))
            lists[label] = listed.stdout
    first = lists["outside-git"]
    for label, text in sorted(lists.items()):
        check("archive-provenance-same-set-%s" % label,
              text == first,
              "enumerated set differs from the outside-git "
              "extraction")
    names = first.splitlines()
    check("archive-provenance-nonempty", len(names) > 100,
          "got %d" % len(names))
    for rel in ("src/memveil/main.mojo", "LICENSE",
                "profiles/manifest.txt", "toolchain.lock.json",
                "THIRD-PARTY-NOTICES.md"):
        check("archive-provenance-keeps-%s"
              % rel.replace("/", "_"),
              rel in names,
              "required input omitted from the inventory")
    with tempfile.TemporaryDirectory(
            prefix="mv-prov-det-a-") as first_tree, \
            tempfile.TemporaryDirectory(
                prefix="mv-prov-det-b-") as second_tree:
        export(first_tree)
        export(second_tree)
        first_digest = inventory_digest(first_tree)
        second_digest = inventory_digest(second_tree)
        check("archive-inventory-deterministic",
              first_digest == second_digest
              and first_digest is not None,
              "inventory digest differs across extractions")
    with tempfile.TemporaryDirectory(
            prefix="mv-prov-neg-") as tree:
        export(tree)
        os.remove(os.path.join(
            tree, "src", "memveil", "main.mojo"))
        proc = run_provenance(tree)
        check("archive-provenance-missing-source-fails",
              proc.returncode != 0,
              "provenance passed without src/memveil/main.mojo")
    with tempfile.TemporaryDirectory(
            prefix="mv-prov-neg-") as tree:
        export(tree)
        os.remove(os.path.join(tree, "LICENSE"))
        proc = run_provenance(tree)
        check("archive-provenance-missing-license-fails",
              proc.returncode != 0,
              "provenance passed without LICENSE")
    with tempfile.TemporaryDirectory(
            prefix="mv-prov-neg-") as tree:
        export(tree)
        manifest = os.path.join(
            tree, "profiles", "manifest.txt")
        with open(manifest, "a") as handle:
            handle.write("no-such-profile.json\n")
        proc = run_provenance(tree)
        check("archive-provenance-altered-manifest-fails",
              proc.returncode != 0,
              "provenance passed with an altered profiles "
              "manifest")
    # Completeness proof: the parent ignores our main entry
    # point, so a gate that trusted the parent's ignore rules
    # would never read it and would pass over the stripped
    # header. The archive inventory must still check it.
    with tempfile.TemporaryDirectory(
            prefix="mv-prov-strip-") as parent:
        init_unrelated(
            parent, ("export/src/memveil/main.mojo",))
        third = os.path.join(parent, "export")
        os.mkdir(third)
        export(third)
        entry = os.path.join(
            third, "src", "memveil", "main.mojo")
        with open(entry) as handle:
            text = handle.read()
        stripped = text.replace(
            "SPDX-License-Identifier:",
            "License-Identifier-Removed:")
        check("archive-provenance-strip-setup",
              stripped != text)
        with open(entry, "w") as handle:
            handle.write(stripped)
        proc = run_provenance(third)
        check("archive-provenance-ignored-source-still-checked",
              proc.returncode != 0,
              "provenance passed with a stripped header on a "
              "parent-ignored source")
    # Hostile-environment proof: foreign repository, work
    # tree, index, and ignore rules must not relocate the
    # ownership comparison or shrink the enumerated set.
    with tempfile.TemporaryDirectory(
            prefix="mv-prov-hostile-") as foreign, \
            tempfile.TemporaryDirectory(
                prefix="mv-prov-neg-") as tree:
        init_unrelated(foreign)
        excludes = os.path.join(foreign, "hostile-excludes")
        with open(excludes, "w") as handle:
            handle.write("src/memveil/__init__.mojo\n")
        export(tree)
        env = hostile_git_env(tree, foreign, excludes)
        listed = run_provenance(tree, "--list-files", env=env)
        check("archive-provenance-hostile-gitenv",
              listed.returncode == 0
              and listed.stdout == first,
              show(listed))
    with tempfile.TemporaryDirectory(
            prefix="mv-prov-hostile-") as foreign, \
            tempfile.TemporaryDirectory(
                prefix="mv-prov-neg-") as tree:
        init_unrelated(foreign)
        excludes = os.path.join(foreign, "hostile-excludes")
        with open(excludes, "w") as handle:
            handle.write("src/memveil/__init__.mojo\n")
        export(tree)
        entry = os.path.join(
            tree, "src", "memveil", "__init__.mojo")
        with open(entry) as handle:
            text = handle.read()
        stripped = text.replace(
            "SPDX-License-Identifier:",
            "License-Identifier-Removed:")
        check("archive-provenance-hostile-strip-setup",
              stripped != text)
        with open(entry, "w") as handle:
            handle.write(stripped)
        env = hostile_git_env(tree, foreign, excludes)
        proc = run_provenance(tree, env=env)
        check("archive-provenance-hostile-stripped-fails",
              proc.returncode != 0
              and "FAIL spdx-coverage" in show(proc),
              show(proc))
    # Strict-traversal proof: unreadable admitted paths
    # must fail loudly, never silently shrink the set.
    with tempfile.TemporaryDirectory(
            prefix="mv-prov-neg-") as tree:
        export(tree)
        proc = subprocess.run(
            ["python3", "-", tree], input=STRICT_PROBE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, cwd=tree, timeout=300)
        check("archive-inventory-strict-failures",
              proc.returncode == 0, show(proc))
    # Membership-guard proof: a required input that exists
    # on disk but is missing from the enumerated set must
    # fail the named check in both enumeration modes. A
    # deleted file would also trip absence checks, so only
    # present-but-unenumerated cases cover the guard.
    with tempfile.TemporaryDirectory(
            prefix="mv-prov-neg-") as tree:
        export(tree)
        init_unrelated(
            tree, ("src/memveil/main.mojo",))
        proc = run_provenance(tree)
        check("archive-provenance-git-ignored-source-fails",
              proc.returncode != 0
              and "FAIL inventory-required-present"
              in show(proc),
              show(proc))
    for label, omit, mode in (
            ("source", "src/memveil/main.mojo", "git"),
            ("license", "LICENSE", "archive")):
        with tempfile.TemporaryDirectory(
                prefix="mv-prov-neg-") as tree:
            export(tree)
            proc = subprocess.run(
                ["python3", "-", tree, omit, mode],
                input=OMITTED_PROBE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True, cwd=tree, timeout=300)
            check("archive-provenance-omitted-%s-fails"
                  % label,
                  proc.returncode == 0, show(proc))


def main():
    rev = subprocess.run(["git", "-C", ROOT, "rev-parse", "HEAD"],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         text=True)
    check("head-readable", rev.returncode == 0)
    head = rev.stdout.strip()
    print("source-export: HEAD %s" % head)

    with tempfile.TemporaryDirectory(
            prefix="mv-export-a-") as first, \
            tempfile.TemporaryDirectory(
                prefix="mv-export-b-") as second:
        export_head(first)
        missing = [rel for rel in REQUIRED
                   if not os.path.isfile(os.path.join(first, rel))]
        check("export-required-inputs", not missing,
              "; ".join(missing[:5]))
        generated = [rel for rel, _, files in os.walk(first)
                     for rel in [os.path.relpath(rel, first)]
                     for marker in GENERATED_MARKERS
                     if ("/" + rel + "/").startswith(marker)
                     or rel in ("build", "dist", ".pixi")]
        check("export-no-generated-dirs", not generated,
              "; ".join(sorted(set(generated))[:5]))
        # Committed fixtures under tests/fixtures are source
        # inputs (object-validation vectors); binaries anywhere
        # else are leaked build outputs.
        stray = []
        for base, _, files in os.walk(first):
            for name in files:
                rel = os.path.relpath(os.path.join(base, name), first)
                if rel.startswith("tests/fixtures/"):
                    continue
                if name.endswith((".o", ".so", ".pyc")) \
                        or ".so." in name:
                    stray.append(rel)
        check("export-no-binaries", not stray, "; ".join(stray[:5]))
        export_head(second)
        check("export-sealed",
              seal(first) == seal(second))
        print("source-export: HEAD export verified "
              "(%d files, mechanism only)" % len(seal(first)))

    archive_provenance_cases(export_head)
    print("source-export: standalone-archive provenance verified")

    # Git-free proof: build and package inside a fresh export.
    # tools/package runs tools/build first; LMB_PACKAGE points
    # at the export's own vendored tarball, never the checkout.
    with tempfile.TemporaryDirectory(prefix="mv-export-c-") as parent:
        # An ignored source export must not inherit even a clean parent's
        # identity, nor refuse packaging because the parent later becomes dirty.
        subprocess.run(["git", "-C", parent, "init", "-q"], check=True)
        with open(os.path.join(parent, ".gitignore"), "w") as handle:
            handle.write("export/\n")
        subprocess.run(["git", "-C", parent, "add", ".gitignore"], check=True)
        subprocess.run(["git", "-C", parent, "-c", "user.name=Test", "-c",
                        "user.email=test@example.invalid", "commit", "-qm",
                        "unrelated"], check=True)
        third = os.path.join(parent, "export")
        os.mkdir(third)
        export_head(third)
        vendored = os.path.join(
            third, "third_party", "libbpf-mojo-0.2.0.tar.gz")
        check("export-vendored-bridge", os.path.isfile(vendored),
              vendored)
        env = dict(os.environ)
        env["LMB_PACKAGE"] = vendored
        pkg = subprocess.run(
            [os.path.join(third, "tools", "package"),
             "--out", os.path.join(third, "dist")],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, cwd=third, env=env, timeout=1500)
        if pkg.returncode != 0:
            print("FAIL export-package: tools/package exited %d"
                  % pkg.returncode)
            print("--- stdout ---")
            print(pkg.stdout[-3000:])
            print("--- stderr ---")
            print(pkg.stderr[-3000:])
            sys.exit(1)
        check("export-package", True)
        import json as _json
        bundles = [name for name in os.listdir(
            os.path.join(third, "dist"))
            if name.startswith("memveil-")
            and os.path.isdir(os.path.join(third, "dist", name))]
        check("export-bundle-dir", len(bundles) == 1,
              "; ".join(bundles))
        manifest = _json.load(open(os.path.join(
            third, "dist", bundles[0], "MANIFEST.json")))
        check("export-revision", manifest.get("memveil_revision")
              == "export", repr(manifest.get("memveil_revision")))
        for rel, want in manifest["files"].items():
            full = os.path.join(third, "dist", bundles[0], rel)
            with open(full, "rb") as handle:
                check("export-hash-%s" % rel,
                      hashlib.sha256(handle.read()).hexdigest() == want)
        sealed = subprocess.run(
            ["python3", "tools/source_inventory.py", "."],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, cwd=third, timeout=300)
        check("export-inventory-runs", sealed.returncode == 0,
              sealed.stderr[-1000:])
        inventory = _json.loads(sealed.stdout or "{}")
        check("export-manifest-inventory",
              manifest.get("source_inventory_digest")
              == inventory.get("digest")
              and manifest.get("source_inventory")
              == inventory.get("files"),
              "manifest inventory must match the exported tree")
        for name in ("troubleshooting.md", "performance.md",
                     "resource-limits.md", "permissions.md",
                     "oracles.md"):
            dest = os.path.join(third, "dist", bundles[0],
                                "docs", name)
            check("export-docs-%s" % name, os.path.isfile(dest),
                  dest)
        prov = run_provenance(third)
        if prov.returncode != 0:
            print("FAIL export-provenance: provenance exited %d "
                  "in the exported tree" % prov.returncode)
            print("--- stdout ---")
            print(prov.stdout[-3000:])
            print("--- stderr ---")
            print(prov.stderr[-3000:])
            sys.exit(1)
        check("export-provenance", True)
        with open(os.path.join(parent, "unrelated-dirty.txt"), "w") as handle:
            handle.write("dirty parent\n")
        repeated = subprocess.run(
            [os.path.join(third, "tools", "package"),
             "--out", os.path.join(third, "dist")],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, cwd=third, env=env, timeout=1500)
        check("export-dirty-parent-package", repeated.returncode == 0,
              repeated.stderr[-3000:])
        with open(os.path.join(third, "dist", bundles[0], "MANIFEST.json")) as handle:
            repeated_manifest = _json.load(handle)
        check("export-dirty-parent-revision",
              repeated_manifest.get("memveil_revision") == "export")
        prov_dirty = run_provenance(third)
        check("export-dirty-parent-provenance",
              prov_dirty.returncode == 0, show(prov_dirty))

    status = subprocess.run(["git", "-C", ROOT, "status", "--short"],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    if status.returncode != 0:
        print("FAIL candidate-clean-tree: cannot inspect worktree")
        sys.exit(1)
    dirty = [line for line in status.stdout.splitlines() if line.strip()]
    if dirty:
        print("source-export: BLOCKED: worktree has uncommitted "
              "changes; commit first (%d paths)" % len(dirty))
        sys.exit(1)
    check("candidate-clean-tree", True)
    print("source-export: candidate export ready at HEAD %s" % head)
    return 0


if __name__ == "__main__":
    sys.exit(main())
