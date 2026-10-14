#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Docs gate: links resolve, commands exist, text stays public.

Every local link in user-facing Markdown resolves to a file and,
for anchored links, a heading; every documented `memveil <verb>`
names a verb from the usage line in main.mojo and every flag
beside it exists in that verb's built --help; and no document
carries placeholder markers. The unit-suite file list in
tools/test is mirrored against that file's header comment.
The claim-vs-receipt audit stays
in the preview-package lane; this lane does not duplicate it.
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


UNIT_LOOP_RE = re.compile(r"for t in (.*); do")
UNIT_FILE_RE = re.compile(r"tests/unit/test_[A-Za-z0-9_]+\.mojo")

# Exact tail of suite_unit(): the reporting block after the
# file loop. The gate pins this body shape; any edit trips
# loudly so a human reconciles the checker with the new
# body instead of drifting silently.
UNIT_TAIL = (
    "done",
    'if [ "$failed" -ne 0 ]; then',
    'echo "unit: FAILED" >&2',
    "return 1",
    "fi",
    'echo "unit: all suites passed"',
    "return 0",
)


def _unit_mentions_ok(lines):
    # True when the name appears only in the canonical
    # definition line (exactly once) and bare call lines:
    # redefinitions in any spelling, unsets, and inline
    # uses trip. Even comments may not name it; reword
    # instead, since a joined artifact could match a
    # whitelisted comment shape.
    found = 0
    for line in lines:
        if "suite_unit" not in line:
            continue
        if line == "suite_unit() {":
            found += 1
            continue
        if line.strip(" \t") == "suite_unit":
            continue
        return False
    return found == 1


def _unit_dispatch_ok(test_src):
    # True when the unit) dispatcher arm invokes the bare
    # call on adjacent lines. Suppressing the call
    # (heredoc data, guards, prefixes, extra lines) breaks
    # the adjacency and trips. Whole-dispatch suppression
    # (a wrap around case/esac, a top-level early exit)
    # keeps this text intact and stays outside this text
    # mirror: it needs execution evidence, which belongs to
    # harness-integrity work, not the selection gate.
    lines = test_src.split("\n")
    arms = [i for i, line in enumerate(lines)
            if line.strip(" \t") == "unit)"]
    if len(arms) != 1:
        return False
    i = arms[0]
    return lines[i:i + 3] == ["    unit)",
                              "        suite_unit",
                              "        ;;"]


def extract_unit_body(test_src):
    # The single suite_unit() definition body, or None.
    # Line-oriented: exactly one canonical definition line,
    # no other mention of the name, body up to the first
    # closing brace at column zero. A carriage return
    # anywhere trips the gate: the file could not run as a
    # shell script anyway. The mention rule runs on physical
    # lines and on continuation-joined logical lines, so a
    # backslash-split redefinition cannot hide from either
    # view. Text shapes that break loudly when run (a
    # missing definition, a syntax error) are the unit
    # lane's own enforcement; this gate rejects shapes that
    # could exit 0 without running the selection.
    if "\r" in test_src:
        return None
    if not _unit_mentions_ok(test_src.split("\n")):
        return None
    joined = test_src.replace("\\\n", "")
    if not _unit_mentions_ok(joined.split("\n")):
        return None
    if not _unit_dispatch_ok(test_src):
        return None
    match = re.search(r"(?m)^suite_unit\(\) \{$", test_src)
    if not match:
        return None
    rest = test_src[match.end():]
    end = re.search(r"(?m)^\}$", rest)
    if not end:
        return None
    return rest[:end.start()]


def unit_body_selection(region):
    # Fail-closed selection check for the suite_unit() body:
    # accepts exactly the known shape (continuation-joined
    # lines, ASCII-blank normalization only; blank lines and
    # full-line comments skipped) and rejects everything
    # else. Filenames must be strict literals, so no
    # quoting, expansion, glob, prefix, or indirection can
    # smuggle a different selection past. Returns (selected,
    # ok); ok is False on any shape the gate does not
    # recognize (never a silent pass).
    if "\r" in region:
        return set(), False
    raw = region.split("\n")
    # Bash ends a comment at its physical newline: a
    # backslash there is comment text, not a continuation.
    # Reject such lines so joining below cannot absorb a
    # following executable line into a discarded comment.
    for line in raw:
        stripped = line.strip(" \t")
        if stripped.startswith("#") and stripped.endswith("\\"):
            return set(), False
    if raw and raw[-1] == "":
        # Drop the boundary split element: the body ends at
        # the closing-brace line, so a continuation reaching
        # it must trip below instead of flushing silently.
        raw.pop()
    joined = []
    buf = ""
    for line in raw:
        if line.endswith("\\"):
            buf += line[:-1]
        else:
            joined.append(buf + line)
            buf = ""
    if buf:
        return set(), False
    lines = [line.strip(" \t") for line in joined]
    lines = [line for line in lines
             if line and not line.startswith("#")]
    if len(lines) != 3 + len(UNIT_TAIL) or lines[0] != "failed=0":
        return set(), False
    match = UNIT_LOOP_RE.fullmatch(lines[1])
    if not match:
        return set(), False
    # The iterator is pinned to t: an exotic name
    # (RANDOM, ROOT, ...) would change what the call
    # argument expands to or clobber run_unit_file's
    # directory.
    files = [word for word in
             re.split(r"[ \t]+", match.group(1)) if word]
    if not files:
        return set(), False
    selected = set()
    for path in files:
        if not UNIT_FILE_RE.fullmatch(path):
            return set(), False
        selected.add(os.path.basename(path))
    if lines[2] != 'run_unit_file "$t" || failed=1':
        return set(), False
    if tuple(lines[3:]) != UNIT_TAIL:
        return set(), False
    return selected, True


EXPECTED_TOP_ROW = ("  top       observe live or replay one capture with"
                    " periodic summaries.")
EXPECTED_RECORD_ROW = ("  record    capture bounce attempts and optional"
                       " lifecycle/copy channels into a directory.")


def unit_file_tokens(text):
    # Prose filename tokens: maximal runs outside
    # whitespace, quotes, and punctuation, kept only when
    # the whole token ends in .mojo with a test_ basename
    # stem. Matching whole tokens first means
    # old_test_runtime.mojo never yields test_runtime.mojo.
    found = set()
    for tok in re.findall(r"[^\s\"'(),;:]+", text):
        if tok.endswith(".mojo") and \
                os.path.basename(tok).startswith("test_"):
            found.add(tok)
    return found


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
        "record", "report", "top", "doctor", "qualify", "help", "version"},
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

    # newline="": read raw bytes so a stray carriage
    # return trips the shape match instead of being
    # translated away.
    test_src = open(os.path.join(ROOT, "tools", "test"),
                    encoding="utf-8", newline="").read()
    header = test_src.split("\n\n")[0]
    check("unit-help-not-everything",
          "runs every Mojo unit test" not in header)
    region = extract_unit_body(test_src)
    check("unit-selection-found", region is not None,
          "suite_unit() not found")
    selected, ok = unit_body_selection(region)
    check("unit-selection-parsed", ok)
    advertised = set(os.path.basename(f) for f in
                     unit_file_tokens(header))
    check("unit-selection-listed", len(selected) >= 1,
          "%d files" % len(selected))
    check("unit-help-matches-selection", advertised == selected,
          "advertised %s selected %s"
          % (sorted(advertised), sorted(selected)))

    print("docs: %d files checked" % len(docs))
    return 0


if __name__ == "__main__":
    sys.exit(main())
