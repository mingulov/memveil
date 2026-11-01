#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Declared candidate assets remain finite and cannot admit a profile."""
from importlib.machinery import SourceFileLoader
from pathlib import Path
import json
ROOT=Path(__file__).resolve().parents[2]
package=SourceFileLoader('journal_package',str(ROOT/'tools/package')).load_module()
assert package._keep_profile('journal-candidates/linux-7.0.14-x86-journal-provisional.json'), 'candidate profile must ship'
assert not package._keep_profile('journal-candidates/foreign.json'), 'undeclared profile accepted'
assert not package._keep_profile('../foreign.json'), 'unsafe profile path accepted'
deb=SourceFileLoader('journal_deb',str(ROOT/'tools/package-deb')).load_module()
assert 'conversion_journal.bpf.o' in deb.BPF_OBJECTS
assert len(deb.BPF_OBJECTS)==4 and len(set(deb.BPF_OBJECTS))==4
profile=json.loads((ROOT/'profiles/journal-candidates/linux-7.0.14-x86-journal-provisional.json').read_text())
assert profile['status']=='unadmitted'
assert all(profile[k] is None for k in ('config_sha256','btf_sha256','object_sha256'))
print('journal asset declaration and non-admission controls passed')
