#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Host-only execution of the shipping probe with bounded helper substitutes."""
from pathlib import Path
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]

def main():
    assert (ROOT / 'bpf/programs/conversion_journal.bpf.c').is_file(), 'shipping journal producer missing'
    with tempfile.TemporaryDirectory() as tmp:
        binary = Path(tmp) / 'producer'
        subprocess.run(['clang', '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', '-I', str(ROOT), '-I', str(ROOT / 'bpf/include'),
                        str(ROOT / 'tests/journal/producer.c'), '-o', str(binary)], check=True)
        subprocess.run([str(binary)], check=True, env=dict(os.environ, UBSAN_OPTIONS='halt_on_error=1'))

if __name__ == '__main__':
    main()
