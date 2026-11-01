#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Inventory and verify canonical runtime bytes, without granting qualification."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat

FORMAT = 'memveil-runtime/1'


def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1048576), b''):
            h.update(chunk)
    return h.hexdigest()


def installed_path(name):
    if name == 'bin/memveil' or name.startswith('lib/memveil/'):
        return 'usr/' + name
    if name.startswith('bpf/'):
        return 'usr/lib/memveil/' + name[4:]
    if name.startswith('profiles/'):
        return 'usr/share/memveil/' + name
    raise ValueError('unknown runtime path: ' + name)


def inventory(root, installed=False):
    root = Path(root)
    if root.is_symlink():
        raise ValueError('runtime root is a symlink')
    prefixes = ('usr/bin', 'usr/lib/memveil', 'usr/share/memveil/profiles') if installed else ('bin', 'lib', 'bpf', 'profiles')
    entries = []
    for prefix in prefixes:
        base = root / prefix
        for parent in (base, *base.parents):
            if parent == root.parent:
                break
            if parent.is_symlink():
                raise ValueError('runtime directory is a symlink: ' + str(parent))
        if not base.is_dir():
            raise ValueError('missing runtime directory: ' + prefix)
        for current, dirs, files in os.walk(base):
            for leaf in dirs + files:
                path = Path(current) / leaf
                mode = path.lstat().st_mode
                if stat.S_ISLNK(mode) or not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                    raise ValueError('unsupported runtime entry: ' + str(path))
            for leaf in sorted(files):
                path = Path(current) / leaf
                name = path.relative_to(root).as_posix()
                if installed:
                    if name.startswith('usr/lib/memveil/') and name.endswith('.bpf.o'):
                        name = 'bpf/' + path.name
                    elif name.startswith('usr/share/memveil/'):
                        name = name[len('usr/share/memveil/'):]
                    else:
                        name = name[4:]
                if name.startswith('lib/') and not name.startswith('lib/memveil/'):
                    raise ValueError('noncanonical library path: ' + name)
                entries.append({'type': 'file', 'path': name, 'sha256': digest(path), 'size': path.stat().st_size})
    return sorted(entries, key=lambda entry: entry['path'])


def verify(root, expected, installed=False):
    actual = inventory(root, installed)
    if actual != expected:
        raise ValueError('runtime inventory differs from canonical manifest')
    return actual


def verify_bundle(root):
    root = Path(root)
    manifest = json.loads((root / 'MANIFEST.json').read_text())
    runtime = manifest['canonical_runtime']
    if runtime['format'] != FORMAT:
        raise ValueError('unsupported canonical runtime format')
    verify(root, runtime['entries'])
    actual = {}
    for current, dirs, files in os.walk(root):
        for name in dirs + files:
            path = Path(current) / name
            mode = path.lstat().st_mode
            if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                raise ValueError('unsupported bundle entry: ' + str(path))
        for name in files:
            path = Path(current) / name
            relative = path.relative_to(root).as_posix()
            if relative != 'MANIFEST.json':
                actual[relative] = digest(path)
    if actual != manifest['files']:
        raise ValueError('bundle files differ from manifest')
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', required=True)
    parser.add_argument('--installed')
    args = parser.parse_args()
    try:
        manifest = verify_bundle(args.bundle)
        if args.installed:
            verify(args.installed, manifest['canonical_runtime']['entries'], installed=True)
    except (OSError, ValueError, KeyError) as error:
        parser.exit(1, 'canonical-runtime: ' + str(error) + '\n')
    print('canonical-runtime: exact bytes verified; qualification not asserted')
