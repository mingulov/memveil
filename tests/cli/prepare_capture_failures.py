#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Build only the test adapters required by standalone failure/path suites."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def prepare():
    inputs = sorted((ROOT / 'src').rglob('*.mojo')) + [
        ROOT / 'tests/unit/checkpoint_probe.mojo', ROOT / 'tests/cli/capture_faults.c',
        ROOT / 'pixi.lock']
    stamp = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}
    stamp['sanitize'] = os.environ.get('LMB_SANITIZE', '0')
    manifest = ROOT / 'build/probe/capture-failure-inputs.json'
    outputs = [ROOT / 'build/probe/checkpoint_probe', ROOT / 'build/shim/capture_faults.so']
    if manifest.exists() and all(p.is_file() for p in outputs):
        saved = json.loads(manifest.read_text())
        if saved.get('inputs') == stamp and saved.get('outputs') == {
                str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in outputs}:
            return
    for output in outputs:
        output.parent.mkdir(parents=True, exist_ok=True)
    sanitizer = ['--sanitize', 'address'] if stamp['sanitize'] == '1' else []
    subprocess.run(['pixi', 'run', '--frozen', 'mojo', 'build', *sanitizer, '-I', 'src',
                    '--target-cpu', 'x86-64-v2', '-o', str(outputs[0]),
                    'tests/unit/checkpoint_probe.mojo'], cwd=ROOT, check=True)
    subprocess.run(['clang', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-shared', '-fPIC',
                    'tests/cli/capture_faults.c', '-o', str(outputs[1])], cwd=ROOT, check=True)
    manifest.write_text(json.dumps(dict(inputs=stamp, outputs={
        str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in outputs}), indent=2) + '\n')


if __name__ == '__main__':
    prepare()
