#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Docs gate: links resolve, commands exist, text stays public.

Scans README.md, AGENTS.md, the root governance files,
docs/**, and examples/**. Every local link in user-facing
Markdown resolves to a file and, for anchored links, a heading; every documented `memveil <verb>`
names a verb from the usage line in main.rs and every flag
beside it exists in that verb's built --help; no document
carries placeholder markers; the support envelope and
the agent instructions carry the identical ratified floor
sentence; every literal copy of the product version equals
the root Cargo.toml version; and every released version
the policy names resolves to a git tag. The claim-vs-receipt
audit stays in the preview-package lane; this lane does
not duplicate it.
"""

import glob
import os
import re
import subprocess
import sys
import tomllib

ROOT = os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))
BIN = os.path.join(ROOT, "build", "memveil")

FORBIDDEN = (
    "TODO", "FIXME", "XXX",
)

# Resolved absence claims: each once contradicted the support
# capability table (shipped periodic pool samples, live top,
# lifecycle/copy channels, shared bridge use). They must never
# come back; the table stays the single support contract.
# Matching runs on normalized text (lowercase, collapsed
# whitespace, no backticks) so rewrapping or restyling cannot
# smuggle a stale claim past the gate.
STALE_ABSENCE = (
    "a live summary is still missing",
    "live top is not implemented",
    "start/end samples",
    "only record loads it",
    "replay-only top",
)

STALE_PROXIMITY_RE = re.compile(
    r"lifecycle.{0,80}separate from shipping")

# The ratified floor sentence, normalized form (see
# normalize): support.md and AGENTS.md must carry the
# identical statement so the two audiences cannot drift.
FLOOR_SENTENCE = (
    "supported collection (ratified 2026-10-31): "
    "attempt-trace from linux 6.0, mapping-lifecycle "
    "and copy-actual from 6.11, qualification ceiling "
    "7.3, btf required."
)


def normalize(text):
    return re.sub(r"\s+", " ", text).lower().replace("`", "")


def fence_spans(text):
    # Line scanner for fenced code blocks: backtick or tilde
    # runs of three or more, up to three leading spaces, and
    # a matching close with a spaces/tabs-only tail. Only
    # ASCII blanks count anywhere: Python's \s also matches
    # Unicode whitespace that Markdown treats as content.
    spans = []
    lines = text.split("\n")
    offsets = []
    pos = 0
    for line in lines:
        offsets.append(pos)
        pos += len(line) + 1
    i = 0
    while i < len(lines):
        opened = re.match(r"^ {0,3}(`{3,}|~{3,})", lines[i])
        if not opened:
            i += 1
            continue
        start = offsets[i]
        fence = opened.group(1)
        if fence[0] == "`" and "`" in lines[i][opened.end():]:
            # Backtick info strings cannot contain backticks:
            # not a fence at all.
            i += 1
            continue
        close_re = r"^ {0,3}(%s{%d,})[ \t]*$" % (
            re.escape(fence[0]), len(fence))
        j = i + 1
        while j < len(lines) and not re.match(close_re, lines[j]):
            j += 1
        if j < len(lines):
            spans.append((start, offsets[j] + len(lines[j])))
            i = j + 1
        else:
            spans.append((start, len(text)))
            i = j
    return spans


def unsupported_section(text):
    # Headings allow up to three spaces; a leading tab is
    # already a code block, so only spaces count here.
    # Fenced code blocks never open or close a section.
    # ASCII blanks only: Unicode whitespace is content.
    spans = fence_spans(text)

    def outside(pos):
        return all(not (start <= pos < end)
                   for start, end in spans)

    starts = [match.start() for match in
              re.finditer(r"(?im)^ {0,3}##[ \t]+unsupported\b", text)
              if outside(match.start())]
    if not starts:
        return ""
    bounds = [match.start() for match in
              re.finditer(r"(?m)^ {0,3}##[ \t]+", text)
              if match.start() > starts[0]
              and outside(match.start())]
    end = bounds[0] if bounds else len(text)
    return text[starts[0]:end]


EXPECTED_TOP_ROW = ("  top           watch live, or replay a capture"
                    " over time")
EXPECTED_RECORD_ROW = ("  record        capture bounce attempts (+ optional"
                       " lifecycle/copy) to a directory (root)")


def verb_line(text, verb):
    for line in text.split("\n"):
        if line.startswith("  %s " % verb):
            return line
    return ""

LINK_RE = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
VERB_RE = re.compile(r"memveil\s+([a-z][a-z-]*)")
FLAG_RE = re.compile(r"--[a-z][a-z-]*")
CODE_RE = re.compile(r"```.*?```|`[^`\n]+`", re.S)
BACKTICK_RE = re.compile(r"`([^`\n]+)`")

# Literal copies of the product version: (relative path,
# regex with exactly one version group). The root
# Cargo.toml [package] version is the truth; every match
# of every pattern must equal it, and every pattern must
# match at least once, so a reworded copy fails loudly
# instead of escaping the gate. Format versions
# (session/event/report/profile/doctor/receipt), history
# (CHANGELOG, older %changelog entries, recorded
# captures), and the internal 0.0.0 crate versions are
# separate namespaces and are not copies.
VERSION_COPIES = (
    ("README.md",
     r"memveil_(\d+\.\d+\.\d+)-1_amd64\.deb"),
    ("README.md",
     r"memveil-(\d+\.\d+\.\d+)\.tar\.gz"),
    ("README.md",
     r"cd memveil-(\d+\.\d+\.\d+)"),
    ("THIRD-PARTY-NOTICES.md",
     r"# Third-party notices \(memveil (\d+\.\d+\.\d+)\)"),
    ("docs/build.md",
     r"dist/memveil-(\d+\.\d+\.\d+)"),
    ("docs/install.md",
     r"memveil_(\d+\.\d+\.\d+)-1_amd64\.deb"),
    ("docs/install.md",
     r"memveil-(\d+\.\d+\.\d+)-1\*\.x86_64\.rpm"),
    ("docs/install.md",
     r"# memveil-(\d+\.\d+\.\d+)-1"),
    ("docs/lifecycle-hooks.md",
     r"development bundle (\d+\.\d+\.\d+)\)"),
    ("docs/profiles.md",
     r"The (\d+\.\d+\.\d+) bundle ships"),
    ("docs/quickstart.md",
     r"development bundle (\d+\.\d+\.\d+)\)"),
    ("docs/quickstart.md",
     r"memveil-(\d+\.\d+\.\d+)\.tar\.gz"),
    ("docs/quickstart.md",
     r"cd memveil-(\d+\.\d+\.\d+)"),
    ("docs/quickstart.md",
     r"# memveil-(\d+\.\d+\.\d+), exit 0"),
    ("docs/recipes/ordinary-linux.md",
     r"which the (\d+\.\d+\.\d+)\s+bundle does not ship"),
    ("docs/release-notes.md",
     r"# MemVeil (\d+\.\d+\.\d+) release notes"),
    ("docs/release-notes.md",
     r"^(\d+\.\d+\.\d+) rebuilds the userspace in Rust"),
    ("docs/release-notes.md",
     r"The hardened (\d+\.\d+\.\d+) ordinary-Linux"),
    ("docs/support.md",
     r"development bundle (\d+\.\d+\.\d+)\)"),
    ("docs/support.md",
     r"`(\d+\.\d+\.\d+)`\s+is a development version"),
    ("docs/support.md",
     r"dist/memveil_(\d+\.\d+\.\d+)-1_amd64\.deb"),
    ("docs/format-compatibility.md",
     r"Product (\d+\.\d+\.\d+) is"),
    ("examples/real-capture/README.md",
     r"the (\d+\.\d+\.\d+) bundle ships reference"),
    ("examples/lifecycle-copy/README.md",
     r"the (\d+\.\d+\.\d+) bundle ships reference"),
    ("packaging/rpm/memveil.spec",
     r"dist/memveil-(\d+\.\d+\.\d+)"),
    ("packaging/rpm/memveil.spec",
     r"^Version:\s+(\d+\.\d+\.\d+)\s*$"),
    # Test and assertion copies: the 0.2.0 bump left
    # these stale while the gate stayed green, so they
    # are pinned here like every other literal copy.
    ("tests/scaffold.rs",
     r"memveil-(\d+\.\d+\.\d+)\\n"),
    ("tools/test",
     r"memveil-(\d+\.\d+\.\d+)"),
    ("src/analysis/attempts.rs",
     r"ENGINE_VERSION, \"memveil-(\d+\.\d+\.\d+)\""),
    ("tests/golden/report-attempts.txt",
     r"engine memveil-(\d+\.\d+\.\d+)\)"),
    ("tests/golden/report-conversion-uncertain.txt",
     r"engine memveil-(\d+\.\d+\.\d+)\)"),
    ("tests/golden/report-copy-before-failure.txt",
     r"engine memveil-(\d+\.\d+\.\d+)\)"),
    ("tests/golden/report-escape.txt",
     r"engine memveil-(\d+\.\d+\.\d+)\)"),
    ("tests/golden/report-gen-lineage.txt",
     r"engine memveil-(\d+\.\d+\.\d+)\)"),
    ("tests/golden/report-lifecycle-nested.txt",
     r"engine memveil-(\d+\.\d+\.\d+)\)"),
    ("tests/golden/report-pool-pressure.txt",
     r"engine memveil-(\d+\.\d+\.\d+)\)"),
    ("tests/golden/report-region-union.txt",
     r"engine memveil-(\d+\.\d+\.\d+)\)"),
    ("tests/golden/report-attempts.md",
     r"- engine: memveil-(\d+\.\d+\.\d+)"),
    ("tests/golden/report-escape.md",
     r"- engine: memveil-(\d+\.\d+\.\d+)"),
)

# TOML copies of the product version: (relative path,
# dotted key path into the parsed document).
VERSION_TOML = (
    ("crates/release-entry/Cargo.toml",
     ("package", "version")),
    ("crates/remap-flags/Cargo.toml",
     ("package", "version")),
    ("Cargo.toml",
     ("dev-dependencies", "memveil-release-entry", "version")),
    ("Cargo.toml",
     ("dev-dependencies", "memveil-remap-flags", "version")),
    ("Cargo.toml",
     ("build-dependencies", "memveil-remap-flags", "version")),
)

# Cargo.lock [[package]] entries tracking the product
# version (the 0.0.0 workspace members are not copies).
VERSION_LOCK_CRATES = (
    "memveil", "memveil-release-entry", "memveil-remap-flags",
)


def check(name, cond, detail=""):
    if not cond:
        print("FAIL %s %s" % (name, detail))
        sys.exit(1)
    print("ok %s" % name)


def version_copies():
    """Error strings for version copies != the Cargo truth.

    Needs no built binary: pure file reads, so it runs
    before the help-text checks below.
    """
    errors = []
    with open(os.path.join(ROOT, "Cargo.toml"), "rb") as handle:
        truth = tomllib.load(handle)["package"]["version"]
    if not re.fullmatch(r"\d+\.\d+\.\d+", truth or ""):
        return ["Cargo.toml [package] version %r is not X.Y.Z"
                % (truth,)]
    for rel, keys in VERSION_TOML:
        with open(os.path.join(ROOT, rel), "rb") as handle:
            found = tomllib.load(handle)
        for key in keys:
            found = found.get(key) \
                if isinstance(found, dict) else None
        if found != truth:
            errors.append("%s %s is %r, want %s"
                          % (rel, ".".join(keys), found, truth))
    with open(os.path.join(ROOT, "Cargo.lock"), "rb") as handle:
        lock = tomllib.load(handle)
    locked = {}
    for entry in lock.get("package", []):
        if isinstance(entry, dict):
            locked[entry.get("name")] = entry.get("version")
    for name in VERSION_LOCK_CRATES:
        if locked.get(name) != truth:
            errors.append("Cargo.lock %s is %r, want %s"
                          % (name, locked.get(name), truth))
    for rel, pattern in VERSION_COPIES:
        with open(os.path.join(ROOT, rel),
                  encoding="utf-8") as handle:
            found = re.findall(pattern, handle.read(),
                               re.MULTILINE)
        if not found:
            errors.append("%s: no match for %r"
                          % (rel, pattern))
        for match in found:
            if match != truth:
                errors.append("%s: copy %r, want %s"
                              % (rel, match, truth))
    # The spec changelog is newest-first: only its head
    # entry tracks the product version; older entries are
    # history and stay frozen.
    with open(os.path.join(ROOT, "packaging", "rpm",
                           "memveil.spec"),
              encoding="utf-8") as handle:
        _head, _sep, tail = handle.read().partition(
            "%changelog")
    match = re.search(r"^\* .* - (\d+\.\d+\.\d+)-1\s*$",
                      tail, re.MULTILINE)
    if match is None:
        errors.append("memveil.spec: no %changelog head entry")
    elif match.group(1) != truth:
        errors.append("memveil.spec %%changelog head is %s, "
                      "want %s" % (match.group(1), truth))
    return errors


def doc_files():
    found = [os.path.join(ROOT, "README.md"),
             os.path.join(ROOT, "AGENTS.md"),
             os.path.join(ROOT, "SECURITY.md"),
             os.path.join(ROOT, "CONTRIBUTING.md"),
             os.path.join(ROOT, "RELEASING.md"),
             os.path.join(ROOT, "CHANGELOG.md")]
    found += sorted(glob.glob(os.path.join(ROOT, "docs", "**", "*.md"),
                              recursive=True))
    found += sorted(glob.glob(os.path.join(ROOT, "examples", "**",
                                           "*.md"), recursive=True))
    return found


def slug(text):
    text = text.strip().lower()
    text = re.sub(r"[^a-z0-9 _-]", "", text)
    return text.replace(" ", "-")


def git_tags():
    """Tag set, or None when ROOT owns no git tree.

    A foreign parent repository's tags must never
    satisfy the policy check: ownership is by top
    level, with symlinks resolved on both sides.
    """
    try:
        top = subprocess.run(
            ["git", "-C", ROOT, "rev-parse", "--show-toplevel"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True)
        if top.returncode != 0:
            return None
        if os.path.realpath(top.stdout.strip()) != \
                os.path.realpath(ROOT):
            return None
        proc = subprocess.run(
            ["git", "-C", ROOT, "tag", "--list"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True)
    except OSError:
        return None
    if proc.returncode != 0:
        return None
    return set(proc.stdout.split())


def headings_of(path):
    slugs = set()
    for line in open(path, encoding="utf-8"):
        match = re.match(r"#{1,6}\s+(.*)", line)
        if match:
            title = re.sub(r"`([^`]*)`", r"\1", match.group(1))
            slugs.add(slug(title))
    return slugs


def main():
    docs = doc_files()
    check("docs-present", len(docs) >= 8, "%d docs" % len(docs))

    usage_src = open(os.path.join(
        ROOT, "src", "main.rs")).read()
    match = re.search(r"usage: memveil <([^>]+)>", usage_src)
    check("verbs-from-source", bool(match))
    verbs = set(match.group(1).split("|"))
    check("verbs-known", verbs == {
        "record", "report", "top", "doctor", "qualify", "bind-profile",
        "help", "version"},
        " ".join(sorted(verbs)))

    copy_errors = version_copies()
    check("version-copies", not copy_errors,
          "; ".join(copy_errors[:5]))

    if not os.path.isfile(BIN):
        print("FAIL docs: missing %s (run cargo build --release first)" % BIN)
        sys.exit(1)
    help_text = {}
    for verb in sorted(verbs):
        if verb in ("help", "version"):
            continue
        proc = subprocess.run([BIN, verb, "--help"],
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True)
        check("help-%s" % verb, proc.returncode == 0)
        help_text[verb] = proc.stdout
    proc = subprocess.run([BIN, "--help"], stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True)
    check("help-top-level", proc.returncode == 0)
    dash_help = proc.stdout
    proc = subprocess.run([BIN, "help"], stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True)
    check("help-verb", proc.returncode == 0)
    verb_help = proc.stdout
    top_help = dash_help + verb_help

    bad_links = []
    bad_verbs = []
    bad_flags = []
    bad_refs = []
    stale = []
    for path in docs:
        rel = os.path.relpath(path, ROOT)
        text = open(path, encoding="utf-8").read()
        norm = normalize(text)
        for phrase in STALE_ABSENCE:
            if phrase in norm:
                stale.append("%s: %r" % (rel, phrase))
        if STALE_PROXIMITY_RE.search(norm):
            stale.append("%s: lifecycle/shipping separation" % rel)
        # The Unsupported section must not re-list shipped
        # capabilities; positive mentions anywhere else stay
        # legitimate.
        unsupported = normalize(unsupported_section(text))
        for term in ("periodic pool", "live summary"):
            if term in unsupported:
                stale.append("%s: unsupported lists %r" % (rel, term))
        for target in LINK_RE.findall(text):
            if re.match(r"(https?://|mailto:|#)", target):
                continue
            file_part, _, anchor = target.partition("#")
            if not file_part:
                continue
            resolved = os.path.normpath(os.path.join(
                os.path.dirname(path), file_part))
            if not os.path.isfile(resolved):
                bad_links.append("%s -> %s" % (rel, target))
            elif anchor and anchor not in headings_of(resolved):
                bad_links.append("%s -> %s (no heading)" % (rel, target))
        # House convention is backticked paths, not inline links:
        # a backticked span naming a Markdown file must resolve
        # beside the doc or at the repo root.
        for span in BACKTICK_RE.findall(text):
            if not span.endswith(".md"):
                continue
            if "/" not in span and span in (
                    "README.md", "AGENTS.md"):
                continue
            for base in (os.path.dirname(path), ROOT):
                if os.path.isfile(os.path.join(base, span)):
                    break
            else:
                bad_links.append("%s -> `%s`" % (rel, span))
        for span in CODE_RE.findall(text):
            for verb in VERB_RE.findall(span):
                if verb not in verbs:
                    bad_verbs.append("%s: memveil %s" % (rel, verb))
                    continue
                if verb in ("help", "version"):
                    continue
                known = set(FLAG_RE.findall(
                    help_text.get(verb, ""))) | {"--help"}
                if verb == "record":
                    known |= set(FLAG_RE.findall(top_help))
                for flag in FLAG_RE.findall(span):
                    if flag not in known:
                        bad_flags.append(
                            "%s: memveil %s %s" % (rel, verb, flag))
        lineno = 0
        for line in text.split("\n"):
            lineno += 1
            for token in FORBIDDEN:
                if token in line:
                    bad_refs.append(
                        "%s:%d: %s" % (rel, lineno, token))
    check("links-resolve", not bad_links, "; ".join(bad_links[:5]))
    check("verbs-exist", not bad_verbs, "; ".join(bad_verbs[:5]))
    check("flags-exist", not bad_flags, "; ".join(bad_flags[:5]))
    check("no-private-refs", not bad_refs, "; ".join(bad_refs[:5]))
    check("no-stale-absence", not stale, "; ".join(stale[:5]))
    for rel in ("docs/support.md", "AGENTS.md"):
        with open(os.path.join(ROOT, rel),
                  encoding="utf-8") as handle:
            found = FLOOR_SENTENCE in normalize(handle.read())
        check("floor-sentence-%s" % slug(rel), found, rel)
    versions = set()
    for rel in ("docs/policy.md", "CHANGELOG.md"):
        with open(os.path.join(ROOT, rel),
                  encoding="utf-8") as handle:
            versions.update(re.findall(r"v\d+\.\d+\.\d+",
                                       handle.read()))
    versions = sorted(versions)
    check("policy-names-versions", len(versions) >= 1,
          "no vX.Y.Z named")
    tags = git_tags()
    if tags is None:
        print("ok policy-tags-resolve "
              "(not an owning checkout; skipped)")
    else:
        missing = [v for v in versions if v not in tags]
        check("policy-tags-resolve", not missing,
              "; ".join(missing))
    help_norm = normalize(dash_help + "\n" + verb_help)
    help_stale = [phrase for phrase in STALE_ABSENCE
                  if phrase in help_norm]
    check("help-no-stale-absence", not help_stale,
          "; ".join(help_stale[:5]))
    for tag, out in (("dash", dash_help), ("verb", verb_help)):
        check("help-%s-top-row" % tag,
              verb_line(out, "top") == EXPECTED_TOP_ROW,
              repr(out[:160]))
        check("help-%s-record-row" % tag,
              verb_line(out, "record") == EXPECTED_RECORD_ROW,
              repr(out[:160]))

    print("docs: %d files checked" % len(docs))
    return 0


if __name__ == "__main__":
    sys.exit(main())
