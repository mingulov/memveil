#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Journal admission must precede all native resource creation."""
from pathlib import Path
import subprocess
import tempfile
ROOT = Path(__file__).resolve().parents[2]

def main():
    with tempfile.TemporaryDirectory() as tmp:
        for verb in ('record','top','qualify'):
            base = [str(ROOT/'build/memveil'),verb,'--output',str(Path(tmp)/verb),
                    '--bridge',str(Path(tmp)/'absent-bridge')]
            for extra, expected, reason in [
                (['--capability','conversion-journal'],3,'journal_profile_not_admitted'),
                (['--capability','conversion-journal','--journal-callers'],3,'journal_profile_not_admitted'),
                (['--capability','conversion-journal','--journal-object','absent.o'],3,'journal_profile_not_admitted'),
                (['--journal-callers'],2,'requires conversion-journal'),
                (['--unknown-journal-control'],2,'unknown option'),
            ]:
                got=subprocess.run(base+extra,capture_output=True,text=True)
                assert got.returncode==expected and reason in got.stderr, (verb,extra,got.returncode,got.stderr)
                assert not (Path(tmp)/verb).exists(), 'refusal created output'
        for verb in ('record','top'):
            got=subprocess.run([str(ROOT/'build/memveil'),verb,'--output',str(Path(tmp)/'pure'),
                                '--capability','conversion-journal','--device','device'],capture_output=True,text=True)
            assert got.returncode==2 and 'global' in got.stderr, got
    print('journal CLI: three selectors, exact admission reasons, no outputs, unknown flag and device controls passed')

if __name__=='__main__': main()
