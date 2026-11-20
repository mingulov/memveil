# SPDX-License-Identifier: GPL-3.0-or-later
"""Exact packaged inputs for qualification.

Development selection stays explicit: without the two
qualification inputs every lookup falls back to its
development default.
"""
import atexit
import os
import shutil
import stat
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import candidate

INPUTS = ('MV_BUNDLE_TARBALL', 'MV_CANDIDATE_MANIFEST')
OVERRIDES = ('MEMVEIL_BIN', 'MV_DEB', 'MV_RPM',
             'MV_KERNELS_BUNDLE', 'LMB_NATIVE_LIB',
             'LD_PRELOAD', 'LD_LIBRARY_PATH', 'LMB_SANITIZE',
             'MEMVEIL_TEST_NO_BPF', 'MV_CANDIDATE_ROOT',
             'MV_REPO')
_cached = None


def requested(env=None):
    env = os.environ if env is None else env
    return any(key in env for key in INPUTS)


def validate_environment(env):
    if not all(env.get(key) for key in INPUTS):
        raise ValueError(
            'qualification requires both MV_BUNDLE_TARBALL '
            'and MV_CANDIDATE_MANIFEST')
    conflicts = [key for key in OVERRIDES if key in env]
    conflicts += [key for key in env
                  if key.startswith('MEMVEIL_TEST_')
                  and key not in conflicts]
    if conflicts:
        raise ValueError('qualification forbids override: '
                         + ', '.join(sorted(conflicts)))


def verify_runtime_bundle(manifest, bundle_path, destination):
    """Verify the exact candidate archive and runtime closure.

    Never builds: the tarball must match the manifest bundle
    artifact, extract to one root without links, and carry the
    pinned manifest bytes, file closure, source, toolchain,
    and build receipt.
    """
    candidate.validate_manifest(manifest)
    candidate.verify_file(
        bundle_path, candidate.artifact(manifest, 'bundle'))
    root = candidate.safe_extract(
        bundle_path, destination, True, False)
    data = candidate.read_regular(root / 'MANIFEST.json')
    candidate.require(
        candidate.digest_bytes(data)
        == manifest['bundle_manifest_sha256'],
        'bundle manifest differs')
    bundled = candidate.verify_bundle_dir(root)
    candidate.require(bundled['files'] == manifest['files'],
                      'bundle closure differs')
    candidate.require(
        bundled['revision'] == manifest['source']['commit'],
        'bundle source differs')
    candidate.require(
        bundled['lock_sha256']
        == manifest['toolchain']['cargo_lock_sha256']
        and bundled['ebpf_lock_sha256']
        == manifest['toolchain']['ebpf_lock_sha256'],
        'bundle toolchain differs')
    receipt = bundled['build_receipt']
    candidate.require(
        candidate.digest_canonical(receipt)
        == manifest['build_receipt_sha256']
        and receipt['source_commit']
        == manifest['source']['commit']
        and receipt['inventory_sha256']
        == manifest['source']['inventory_sha256'],
        'bundle build differs')
    return root


class CandidateInput:
    def __init__(self, env):
        validate_environment(env)
        self.manifest_path = Path(
            env['MV_CANDIDATE_MANIFEST']).absolute()
        self.bundle = Path(env['MV_BUNDLE_TARBALL']).absolute()
        self.manifest = candidate.load_manifest(
            self.manifest_path, env.get('MV_CANDIDATE_DIGEST'))
        self.digest = candidate.digest_bytes(
            candidate.canonical(self.manifest))
        self._directory = Path(
            tempfile.mkdtemp(prefix='memveil-candidate-'))
        self._directory_fd = os.open(
            self._directory,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self._identity = os.fstat(self._directory_fd)
        try:
            self.root = verify_runtime_bundle(
                self.manifest, self.bundle,
                self._directory / 'runtime')
        except BaseException:
            self.close()
            raise
        self.bin = self.root / 'bin/memveil'
        if not os.access(self.bin, os.X_OK):
            self.close()
            raise ValueError(
                'candidate executable lacks execute '
                'permission')

    def artifact(self, role):
        return self.artifact_path(role)

    def artifact_path(self, role):
        if not isinstance(role, str) \
                or role not in candidate.ROLES:
            raise ValueError(
                'unknown candidate artifact role: %r'
                % (role,))
        entry = candidate.artifact(self.manifest, role)
        path = self.bundle if role == 'bundle' \
            else self.manifest_path.parent / entry['name']
        candidate.verify_file(path, entry)
        return path

    def path(self, relative):
        candidate.relative(relative)
        if relative not in self.manifest['files']:
            raise ValueError(
                'input outside candidate closure: ' + relative)
        path = self.root / relative
        if path.is_symlink() \
                or candidate.digest(path) \
                != self.manifest['files'][relative]:
            raise ValueError(
                'candidate input changed: ' + relative)
        return path

    def close(self):
        if self._directory_fd is None:
            return
        descriptor, self._directory_fd = \
            self._directory_fd, None
        try:
            current = self._directory.lstat()
            if ((current.st_dev, current.st_ino)
                    != (self._identity.st_dev,
                        self._identity.st_ino)
                    or not stat.S_ISDIR(current.st_mode)):
                raise ValueError(
                    'candidate extraction ownership changed; '
                    'cleanup refused')
            os.lseek(descriptor, 0, os.SEEK_SET)
            for name in os.listdir(descriptor):
                info = os.stat(name, dir_fd=descriptor,
                               follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    shutil.rmtree(name, dir_fd=descriptor)
                else:
                    os.unlink(name, dir_fd=descriptor)
            current = self._directory.lstat()
            if (current.st_dev, current.st_ino) \
                    != (self._identity.st_dev,
                        self._identity.st_ino):
                raise ValueError(
                    'candidate extraction ownership changed; '
                    'directory removal refused')
            self._directory.rmdir()
        finally:
            os.close(descriptor)


def load(env=None, required=False):
    global _cached
    supplied = os.environ if env is None else env
    if not requested(supplied):
        if required:
            raise ValueError(
                'qualification requires both '
                'MV_BUNDLE_TARBALL and MV_CANDIDATE_MANIFEST')
        return None
    validate_environment(supplied)
    if env is not None:
        return CandidateInput(supplied)
    if _cached is None:
        _cached = CandidateInput(supplied)
        atexit.register(_cached.close)
    elif (_cached.manifest_path
            != Path(supplied[INPUTS[1]]).absolute()
            or _cached.bundle
            != Path(supplied[INPUTS[0]]).absolute()):
        raise ValueError('candidate inputs changed within runner')
    return _cached


def binary(development, explicit=None, env=None):
    selected = load(env)
    if selected:
        if explicit is not None \
                and Path(explicit).absolute() != selected.bin:
            raise ValueError('qualification forbids conflicting '
                             '--binary override')
        return str(selected.path('bin/memveil'))
    return str(explicit or (os.environ if env is None else env)
               .get('MEMVEIL_BIN') or development)
