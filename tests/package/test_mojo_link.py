# SPDX-License-Identifier: GPL-3.0-or-later
"""The linker adapter preserves the selected driver and changes only its SDK RPATH."""
import importlib.util
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))


def adapter():
    assert importlib.util.find_spec('mojo_link') is not None, 'native link adapter is missing'
    import mojo_link
    return mojo_link


def invocation(sdk):
    return ['object.a', sdk + '/libKGENCompilerRTShared.so', '-Xlinker', '-rpath',
            '-Xlinker', sdk, '-o', 'build/memveil', '-Wl,--gc-sections', '-lm']


def test_only_driver_sdk_rpath_changes():
    args = invocation('/sdk/lib')
    actual = adapter().normalize(args, '/sdk/lib', '$ORIGIN/../.pixi/envs/default/lib')
    expected = list(args)
    expected[5] = '$ORIGIN/../.pixi/envs/default/lib'
    assert actual == expected
    assert args == invocation('/sdk/lib')


@pytest.mark.parametrize('kind', ['missing', 'foreign', 'duplicate', 'unexpected', 'joined'])
def test_unexpected_linker_search_paths_refuse(kind):
    args = invocation('/sdk/lib')
    if kind == 'missing':
        del args[2:6]
    elif kind == 'foreign':
        args[5] = '/foreign/lib'
    elif kind == 'duplicate':
        args += args[2:6]
    elif kind == 'unexpected':
        args += ['-Xlinker', '-rpath', '-Xlinker', '/foreign/lib']
    else:
        args += ['-Wl,-rpath,/foreign/lib']
    with pytest.raises(ValueError):
        adapter().normalize(args, '/sdk/lib', '$ORIGIN/../.pixi/envs/default/lib')


def test_adapter_restores_path_and_preserves_every_other_argument(tmp_path):
    import json
    import os
    import subprocess
    driver = tmp_path / 'driver'
    result_file = tmp_path / 'result.json'
    driver.write_text('#!/usr/bin/env python3\nimport json,os,sys\nfrom pathlib import Path\nPath(os.environ["RESULT"]).write_text(json.dumps([sys.argv[1:],os.environ["PATH"]]))\n')
    driver.chmod(0o755)
    args = invocation('/sdk/lib')
    env = dict(os.environ, MEMVEIL_LINK_CC=str(driver), MEMVEIL_LINK_PATH='/usr/bin:/bin',
               MEMVEIL_LINK_SDK_LIB='/sdk/lib', MEMVEIL_LINK_RUNPATH='$ORIGIN/../lib/memveil',
               RESULT=str(result_file))
    proc = subprocess.run([sys.executable, str(ROOT / 'tools/native-link/cc'), *args], env=env,
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    actual, path = json.loads(result_file.read_text())
    expected = list(args)
    expected[5] = '$ORIGIN/../lib/memveil'
    assert actual == expected
    assert path == '/usr/bin:/bin'
    result_file.unlink()
    proc = subprocess.run([sys.executable, str(ROOT / 'tools/native-link/cc'), *args,
                           '-Wl,-rpath,/escape'], env=env, capture_output=True, text=True)
    assert proc.returncode != 0
    assert not result_file.exists(), 'rejected arguments reached the real driver'
