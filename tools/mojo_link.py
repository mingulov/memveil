#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Keep the Mojo host linker search path independent of the SDK prefix."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
SHIM = ROOT / 'tools/native-link'


def normalize(argv, sdk_library, runpath):
    expected = ['-Xlinker', '-rpath', '-Xlinker', sdk_library]
    starts = [i for i in range(len(argv) - 3) if argv[i:i + 4] == expected]
    if len(starts) != 1:
        raise ValueError('expected exactly one driver-owned SDK RPATH')
    start = starts[0]
    for i, arg in enumerate(argv):
        if i == start + 1:
            continue
        tokens = arg[4:].split(',') if arg.startswith('-Wl,') else [arg]
        if any(token.startswith('-') and
               ('rpath' in token.lower() or token.startswith('-R')) for token in tokens):
            raise ValueError('unexpected linker search-path option')
    result = list(argv)
    result[start + 3] = runpath
    return result


def identities():
    driver = shutil.which('cc')
    if driver is None:
        raise ValueError('required native link driver missing: cc')
    selected = {'cc_launcher': driver}
    compiler = driver
    if Path(driver).resolve().name == 'ccache':
        configured = subprocess.check_output(
            [str(Path(driver).resolve()), '--get-config', 'compiler'], text=True).strip()
        if configured:
            compiler = shutil.which(configured)
        else:
            compiler = next((str(Path(directory) / 'cc')
                             for directory in os.environ['PATH'].split(os.pathsep)
                             if (Path(directory) / 'cc').is_file()
                             and os.access(Path(directory) / 'cc', os.X_OK)
                             and (Path(directory) / 'cc').resolve() != Path(driver).resolve()), None)
        if not compiler:
            raise ValueError('cannot identify the compiler selected by ccache')
    selected['cc'] = compiler
    for name in ('ld', 'collect2'):
        tool = subprocess.check_output([driver, '-print-prog-name=' + name], text=True).strip()
        resolved = tool if os.path.isabs(tool) else shutil.which(tool)
        if resolved and Path(resolved).is_file():
            selected[name] = resolved
        elif name == 'ld':
            raise ValueError('cannot identify the native linker')
    result = {}
    for name, path in selected.items():
        version_path = str(Path(path).resolve()) if name == 'cc_launcher' else path
        version = subprocess.check_output([version_path, '--version'], text=True,
                                          stderr=subprocess.STDOUT).splitlines()[0]
        result[name] = {'version': version, 'executable': Path(path).resolve().name,
                        'sha256': hashlib.sha256(Path(path).read_bytes()).hexdigest()}
    return result


def cc_main():
    try:
        driver = os.environ['MEMVEIL_LINK_CC']
        original_path = os.environ['MEMVEIL_LINK_PATH']
        sdk = os.environ['MEMVEIL_LINK_SDK_LIB']
        runpath = os.environ['MEMVEIL_LINK_RUNPATH']
        args = normalize(sys.argv[1:], sdk, runpath)
        if not Path(driver).is_absolute() or Path(driver).resolve() == (SHIM / 'cc').resolve():
            raise ValueError('invalid native link driver')
    except (KeyError, ValueError) as error:
        sys.exit('mojo-link: ' + str(error))
    env = dict(os.environ, PATH=original_path)
    os.execve(driver, [driver, *args], env)


def main(argv):
    driver = shutil.which('cc')
    mojo = shutil.which('mojo')
    if not driver or not mojo:
        sys.exit('mojo-link: run inside the frozen pixi environment with cc available')
    if Path(driver).resolve() == (SHIM / 'cc').resolve():
        sys.exit('mojo-link: nested linker adapter refused')
    if argv.count('-o') != 1 or argv.index('-o') + 1 == len(argv):
        sys.exit('mojo-link: require exactly one explicit output')
    output = Path(argv[argv.index('-o') + 1]).absolute()
    sdk_lib = ROOT / '.pixi/envs/default/lib'
    relative = os.path.relpath(sdk_lib, output.parent)
    env = dict(os.environ, MEMVEIL_LINK_CC=driver, MEMVEIL_LINK_PATH=os.environ['PATH'],
               MEMVEIL_LINK_SDK_LIB=str(sdk_lib), MEMVEIL_LINK_RUNPATH='$ORIGIN/' + relative,
               PATH=str(SHIM) + os.pathsep + os.environ['PATH'])
    os.execve(mojo, [mojo, 'build', *argv], env)


if __name__ == '__main__':
    main(sys.argv[1:])
