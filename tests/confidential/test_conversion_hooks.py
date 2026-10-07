#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Conversion hook evidence: names are not admission.

Collects kernel symbol evidence for the candidate conversion APIs
(set_memory_encrypted/set_memory_decrypted) from kallsyms and BTF
presence, and refuses hook admission: a name in kallsyms proves
nothing about signature stability, return-code meaning, or rollback
behavior. Admission needs per-hook kernel-source inspection plus a
return/rollback proof that does not exist here.

Runs unprivileged. Exit 0 when every assertion holds, 1 otherwise.
Python standard library only.
"""

import json
import os
import platform
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from hooks import CANDIDATE_APIS, collect_evidence, parse_kallsyms

PRESENT_VECTOR = """\
0000000000000000 T __pfx_set_memory_decrypted
0000000000000000 T set_memory_decrypted
0000000000000000 T __pfx_set_memory_encrypted
0000000000000000 T set_memory_encrypted
0000000000000000 t some_static_helper
"""

ABSENT_VECTOR = """\
0000000000000000 T start_kernel
0000000000000000 t some_static_helper
"""

LOCAL_VECTOR = """\
0000000000000000 t set_memory_encrypted
"""


def check_present_vector():
    found = parse_kallsyms(PRESENT_VECTOR)
    assert found == {"set_memory_decrypted": "global-text",
                     "set_memory_encrypted": "global-text"}, found
    assert "__pfx_set_memory_encrypted" not in found


def check_absent_vector():
    assert parse_kallsyms(ABSENT_VECTOR) == {}


def check_local_vector():
    found = parse_kallsyms(LOCAL_VECTOR)
    assert found == {"set_memory_encrypted": "local-text"}, found


def check_verdict_refused():
    for symbols in ({"set_memory_encrypted": "global-text",
                     "set_memory_decrypted": "global-text"}, {}):
        verdict = collect_evidence(symbols, True, "9.9.9-test")
        assert verdict["admission"] == "refused", verdict
        assert "kernel-source" in verdict["reason"], verdict
        assert set(verdict["symbols"]) == set(CANDIDATE_APIS), verdict
        assert verdict["kernel_release"] == "9.9.9-test", verdict


def check_live():
    try:
        with open("/proc/kallsyms", "r", encoding="utf-8",
                  errors="replace") as handle:
            text = handle.read()
        readable = True
    except OSError:
        text = ""
        readable = False
    symbols = parse_kallsyms(text)
    btf = os.path.exists("/sys/kernel/btf/vmlinux")
    verdict = collect_evidence(symbols, btf, platform.uname().release,
                               readable)
    assert verdict["kernel_release"] == platform.uname().release
    assert verdict["kallsyms_readable"] is readable
    assert verdict["btf_present"] is btf
    assert verdict["admission"] == "refused"
    assert "kernel-source" in verdict["reason"]
    for name in CANDIDATE_APIS:
        entry = verdict["symbols"][name]
        assert isinstance(entry["present"], bool)
        if entry["present"]:
            assert entry["kind"] in ("global-text", "local-text"), entry
        else:
            assert entry["kind"] is None, entry
    return verdict


def main():
    checks = (("present-vector", check_present_vector),
              ("absent-vector", check_absent_vector),
              ("local-vector", check_local_vector),
              ("verdict-refused", check_verdict_refused))
    failed = 0
    for label, check in checks:
        try:
            check()
        except AssertionError as exc:
            print("FAIL %s: %s" % (label, exc))
            failed += 1
            continue
        print("ok %s" % label)
    try:
        verdict = check_live()
    except AssertionError as exc:
        print("FAIL live: %s" % exc)
        return 1
    print("ok live")
    print("live evidence: %s" % json.dumps(verdict, sort_keys=True))
    if failed:
        return 1
    print("conversion-hooks: 5/5 checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
