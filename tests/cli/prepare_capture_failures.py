#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Build only the test adapters required by standalone failure/path suites."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]

# Output shim: C source. The shims stay uninstrumented even in
# sanitizer runs: they are LD_PRELOADed, and a statically linked
# sanitizer runtime inside a preloaded library aborts ASan init
# ("runtime does not come first"); the preloaded-into binaries
# stay fully checked. (The Mojo probe binaries formerly built
# here retired with the Mojo tree; their suites gate with cause.)
SHIMS = {
    'build/shim/capture_faults.so': 'tests/cli/capture_faults.c',
    'build/shim/checkpoint_faults.so': 'tests/shim/checkpoint_faults.c',
    'build/shim/mvshim.so': 'tests/shim/mvshim.c',
}
CC = ['clang', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
      '-shared', '-fPIC']


def prepare():
    inputs = sorted(ROOT / src for src in SHIMS.values())
    stamp = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
    manifest = ROOT / 'build/shim/capture-failure-inputs.json'
    outputs = [ROOT / rel for rel in SHIMS]
    if manifest.exists() and all(p.is_file() for p in outputs):
        saved = json.loads(manifest.read_text())
        if saved.get('inputs') == stamp and saved.get('outputs') == {
                str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in outputs}:
            return
    for output in outputs:
        output.parent.mkdir(parents=True, exist_ok=True)
    for rel, src in SHIMS.items():
        subprocess.run([*CC, '-o', str(ROOT / rel), str(ROOT / src)],
                       cwd=ROOT, check=True)
    manifest.write_text(json.dumps(dict(inputs=stamp, outputs={
        str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in outputs}), indent=2) + '\n')


if __name__ == '__main__':
    prepare()
