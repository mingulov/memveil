#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Docs gate: links resolve, commands exist, text stays public.

Every local link in user-facing Markdown resolves to a file and,
for anchored links, a heading; every documented `memveil <verb>`
names a verb from the usage line in main.mojo and every flag
beside it exists in that verb's built --help; and no document
references umbrella-private paths, workspace locations, or
placeholder markers. The claim-vs-receipt audit stays in the
preview-package lane; this lane does not duplicate it.
"""

import glob
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))
BIN = os.path.join(ROOT, "build", "memveil")

FORBIDDEN = (
    "doc/plans", "doc/validation", "repos/memveil",
    "repos/libbpf-mojo", "memveil-ws", "/work/", "task-index",
    "TODO", "FIXME", "XXX",
)

LINK_RE = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
VERB_RE = re.compile(r"memveil\s+([a-z][a-z-]*)")
FLAG_RE = re.compile(r"--[a-z][a-z-]*")
CODE_RE = re.compile(r"```.*?```|`[^`\n]+`", re.S)
BACKTICK_RE = re.compile(r"`([^`\n]+)`")


def check(name, cond, detail=""):
    if not cond:
        print("FAIL %s %s" % (name, detail))
        sys.exit(1)
    print("ok %s" % name)


def doc_files():
    found = [os.path.join(ROOT, "README.md"),
             os.path.join(ROOT, "AGENTS.md")]
    found += sorted(glob.glob(os.path.join(ROOT, "docs", "**", "*.md"),
                              recursive=True))
    found += sorted(glob.glob(os.path.join(ROOT, "examples", "**",
                                           "*.md"), recursive=True))
    return found


def slug(text):
    text = text.strip().lower()
    text = re.sub(r"[^a-z0-9 _-]", "", text)
    return text.replace(" ", "-")


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
        ROOT, "src", "memveil", "main.mojo")).read()
    match = re.search(r"usage: memveil <([^>]+)>", usage_src)
    check("verbs-from-source", bool(match))
    verbs = set(match.group(1).split("|"))
    check("verbs-known", verbs == {
        "record", "report", "top", "doctor", "help", "version"},
        " ".join(sorted(verbs)))

    if not os.path.isfile(BIN):
        print("FAIL docs: missing %s (run tools/build first)" % BIN)
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
    top_help = proc.stdout + subprocess.run(
        [BIN, "help"], stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True).stdout

    bad_links = []
    bad_verbs = []
    bad_flags = []
    bad_refs = []
    for path in docs:
        rel = os.path.relpath(path, ROOT)
        text = open(path, encoding="utf-8").read()
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

    print("docs: %d files checked" % len(docs))
    return 0


if __name__ == "__main__":
    sys.exit(main())
