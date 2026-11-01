# SPDX-License-Identifier: GPL-3.0-or-later
"""Exact packaged inputs for qualification; development selection stays explicit."""
import atexit
import hashlib
import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import candidate

INPUTS = ('MV_BUNDLE_TARBALL', 'MV_CANDIDATE_MANIFEST')
OVERRIDES = ('MEMVEIL_BIN', 'MV_DEB', 'MV_RPM', 'MV_KERNELS_BUNDLE',
             'LMB_NATIVE_LIB', 'LD_PRELOAD', 'LD_LIBRARY_PATH', 'LMB_SANITIZE',
             'MEMVEIL_TEST_NO_BPF', 'MV_CANDIDATE_ROOT', 'MV_REPO')
_cached = None


def requested(env=None):
    env = os.environ if env is None else env
    return any(key in env for key in INPUTS)


def validate_environment(env):
    if not all(env.get(key) for key in INPUTS):
        raise ValueError('qualification requires both MV_BUNDLE_TARBALL and MV_CANDIDATE_MANIFEST')
    conflicts = [key for key in OVERRIDES if key in env]
    conflicts += [key for key in env if key.startswith('MEMVEIL_TEST_') and key not in conflicts]
    if conflicts:
        raise ValueError('qualification forbids override: ' + ', '.join(sorted(conflicts)))


class CandidateInput:
    def __init__(self, env):
        validate_environment(env)
        self.manifest_path = Path(env['MV_CANDIDATE_MANIFEST']).absolute()
        self.bundle = Path(env['MV_BUNDLE_TARBALL']).absolute()
        self.manifest = candidate.load_manifest(self.manifest_path, env.get('MV_CANDIDATE_DIGEST'))
        self.digest = candidate.digest_bytes(candidate.canonical(self.manifest))
        self._owner = tempfile.TemporaryDirectory(prefix='memveil-candidate-')
        try:
            self.root = candidate.verify_bundle(self.manifest, self.bundle, Path(self._owner.name) / 'runtime')
        except BaseException:
            self._owner.cleanup()
            raise
        self.bin = self.root / 'bin/memveil'
        if not os.access(self.bin, os.X_OK):
            self.close()
            raise ValueError('candidate executable lacks execute permission')

    def artifact(self, role):
        entry = candidate.artifact(self.manifest, role)
        path = self.bundle if role == 'bundle' else self.manifest_path.parent / entry['name']
        candidate.verify_file(path, entry)
        return path

    def path(self, relative):
        candidate.relative(relative)
        if relative not in self.manifest['files']:
            raise ValueError('input outside candidate closure: ' + relative)
        path = self.root / relative
        if path.is_symlink() or candidate.runtime.digest(path) != self.manifest['files'][relative]:
            raise ValueError('candidate input changed: ' + relative)
        return path

    def close(self):
        self._owner.cleanup()


def load(env=None, required=False):
    global _cached
    supplied = os.environ if env is None else env
    if not requested(supplied):
        if required:
            raise ValueError('qualification requires both MV_BUNDLE_TARBALL and MV_CANDIDATE_MANIFEST')
        return None
    validate_environment(supplied)
    if env is not None:
        return CandidateInput(supplied)
    if _cached is None:
        _cached = CandidateInput(supplied)
        atexit.register(_cached.close)
    elif (_cached.manifest_path != Path(supplied[INPUTS[1]]).absolute() or
          _cached.bundle != Path(supplied[INPUTS[0]]).absolute()):
        raise ValueError('candidate inputs changed within runner')
    return _cached


def binary(development, explicit=None, env=None):
    selected = load(env)
    if selected:
        if explicit is not None and Path(explicit).absolute() != selected.bin:
            raise ValueError('qualification forbids conflicting --binary override')
        return str(selected.path('bin/memveil'))
    return str(explicit or (os.environ if env is None else env).get('MEMVEIL_BIN') or development)
