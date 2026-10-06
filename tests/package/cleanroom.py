# SPDX-License-Identifier: GPL-3.0-or-later

"""Pure clean-room audit helpers (unit-tested, no subprocesses).

audit_trace() reassembles split strace records by PID, resolves
relative opens against the known working directory, and reports
successful collection-input access as violation strings (empty
means clean). check_manifest() compares a bundle tree against
its MANIFEST.json keys exactly.
"""

import os

# Syscalls whose successful file access the audit inspects. The
# lane traces exactly this set (plus execve, inspected elsewhere).
TRACED_FILE_CALLS = ("openat", "open", "openat2")

# Collection inputs: a *successful* open of one of these is a
# violation. The language runtime's read-only device/cgroup
# inventory is deliberately not listed: it is not a collection
# input and cannot influence the byte-asserted report.
DIR_BANS = ("/sys/kernel", "/sys/fs/bpf")
SUFFIX_BANS = (".bpf.o",)

# Substrings that must never appear in a successfully opened path.
SUBSTRING_BANS = (".pixi", "libbpf")

# /proc carve-outs for the runtime's read-only topology reads.
PROC_BENIGN = ("/proc/self/", "/proc/cpuinfo")


def reassemble(records):
    """Join split strace records by PID.

    Takes raw trace lines; returns (completed, problems) where
    completed holds one joined line per finished call and
    problems names truncated input (unfinished records with no
    resume, resumes with no start). Joined lines keep the PID
    prefix and the resumed return value.
    """
    pending = {}
    completed = []
    problems = []
    for line in records:
        if not line.split():
            continue
        if "<unfinished" in line:
            pid = line.split(None, 1)[0]
            if pid in pending:
                problems.append("dup unfinished: %s" % line)
            pending[pid] = line.split("<unfinished")[0].rstrip()
            continue
        if "resumed>" in line:
            pid = line.split(None, 1)[0]
            head = pending.pop(pid, None)
            if head is None:
                problems.append("orphan resume: %s" % line)
                continue
            tail = line.split("resumed>", 1)[1].strip()
            completed.append("%s %s" % (head, tail))
            continue
        completed.append(line)
    for pid in sorted(pending):
        problems.append("truncated: %s" % pending[pid])
    return completed, problems


def _split_args(call):
    """Split a joined call's argument list on top-level commas."""
    depth = 0
    in_str = False
    esc = False
    cur = []
    out = []
    for ch in call:
        if in_str:
            cur.append(ch)
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
            cur.append(ch)
        elif ch == "(":
            depth += 1
            cur.append(ch)
        elif ch == ")":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    out.append("".join(cur).strip())
    return out


def _unquote(text):
    if len(text) >= 2 and text.startswith('"') and text.endswith('"'):
        return text[1:-1]
    return text


def _outcome(line):
    """Call outcome: True (success), False (failure), None (unknown).

    The return value is read after the call's own closing
    parenthesis, found by a quote-aware scan: quoted filenames
    may contain parens and ") = " markers. A missing
    terminator, a missing "=", or an empty/unknown return is
    indeterminate, never a pass.
    """
    try:
        open_i = line.index("(")
    except ValueError:
        return None
    depth = 0
    in_str = False
    esc = False
    close_i = None
    for i in range(open_i, len(line)):
        ch = line[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                close_i = i
                break
    if close_i is None:
        return None
    tail = line[close_i + 1:].strip()
    if not tail.startswith("="):
        return None
    toks = tail[1:].strip().split(None, 1)
    if not toks or not toks[0] or toks[0] == "?":
        return None
    return not toks[0].startswith("-")


def _resolve(path, cwd):
    """Absolute normalized path for cwd-relative opens.

    Leading slash runs collapse to one (Linux treats //foo as
    /foo, but normpath preserves exactly two).
    """
    if not path.startswith("/"):
        path = os.path.join(cwd, path)
    path = os.path.normpath(path)
    while path.startswith("//"):
        path = path[1:]
    return path


def _within(path, prefix):
    """True when path equals prefix or sits below it."""
    return path == prefix or path.startswith(prefix.rstrip("/") + "/")


def audit_trace(text, cwd, repo_prefix):
    """Audit one strace log; return violation strings (empty=clean).

    cwd is the traced process's working directory (relative opens
    resolve against it; a successful chdir/fchdir is itself a
    violation). repo_prefix is the checkout path whose
    appearance in a successful open is a violation.
    """
    completed, problems = reassemble(text.splitlines())
    violations = ["trace: %s" % p for p in problems]
    for line in completed:
        if not line.split():
            continue
        if "resumed>" in line or "<unfinished" in line:
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        call = parts[1]
        name = call.split("(", 1)[0]
        if name not in TRACED_FILE_CALLS and name not in (
                "chdir", "fchdir", "socket", "connect",
                "sendto", "bpf"):
            continue
        outcome = _outcome(line)
        if outcome is None:
            violations.append("indeterminate: %s" % line)
            continue
        if name in ("chdir", "fchdir"):
            if outcome:
                violations.append("chdir: %s" % line)
            continue
        if name in ("socket", "connect", "sendto", "bpf"):
            if outcome:
                violations.append("net/bpf: %s" % line)
            continue
        if not outcome:
            continue
        body = call.split("(", 1)[1].rsplit(")", 1)[0]
        args = _split_args(body)
        if name in ("openat", "openat2") and len(args) >= 2:
            dirfd, raw = args[0], _unquote(args[1])
            if not raw.startswith("/") and dirfd != "AT_FDCWD":
                violations.append("dirfd-relative: %s" % line)
                continue
            path = _resolve(raw, cwd)
        elif name == "open" and len(args) >= 1:
            path = _resolve(_unquote(args[0]), cwd)
        else:
            violations.append("unparsed: %s" % line)
            continue
        for ban in DIR_BANS:
            if _within(path, ban):
                violations.append("banned %s: %s" % (ban, line))
        for ban in SUFFIX_BANS:
            if path.endswith(ban):
                violations.append("banned %s: %s" % (ban, line))
        for ban in SUBSTRING_BANS:
            if ban in path:
                violations.append("banned %s: %s" % (ban, line))
        if repo_prefix and _within(path, repo_prefix):
            violations.append("checkout: %s" % line)
        if path.startswith("/proc/") \
                and not path.startswith(PROC_BENIGN):
            violations.append("proc: %s" % line)
    return violations


def check_manifest(root, manifest):
    """Exact manifest/tree comparison; return problem strings."""
    problems = []
    want = manifest.get("files", {})
    critical = (
        "bin/memveil",
        "lib/libbpf_mojo.so.1",
        "bpf/swiotlb_attempt.bpf.o",
        "profiles/manifest.txt",
        "LICENSE",
        "THIRD-PARTY-NOTICES.md",
    )
    for rel in critical:
        if rel not in want:
            problems.append("manifest omits critical %s" % rel)
    disk = set()
    for base, _, files in os.walk(root):
        for name in files:
            rel = os.path.relpath(os.path.join(base, name), root)
            if rel != "MANIFEST.json":
                disk.add(rel)
    for rel in sorted(set(want) - disk):
        problems.append("manifest lists missing %s" % rel)
    for rel in sorted(disk - set(want)):
        problems.append("unlisted payload file %s" % rel)
    return problems
