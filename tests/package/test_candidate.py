# SPDX-License-Identifier: GPL-3.0-or-later
"""Synthetic custody fixtures never qualify a product artifact."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tarfile

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))


def api():
    assert importlib.util.find_spec('candidate'), 'candidate protocol is missing'
    import candidate
    return candidate


def sha(data):
    return hashlib.sha256(data).hexdigest()


def manifest():
    return {'schema': 'memveil-candidate/1', 'origin': 'local-build',
            'source': {'commit': 'a' * 40, 'tree': 'b' * 40, 'inventory_sha256': 'c' * 64},
            'toolchain': {'lock_sha256': 'd' * 64, 'pixi_lock_sha256': 'e' * 64},
            'build_receipt_sha256': 'f' * 64, 'bundle_manifest_sha256': '1' * 64,
            'policy_sha256': '2' * 64,
            'canonical_runtime': {'format': 'memveil-runtime/1', 'cpu': {
                'code_generation': 'x86-64-v2', 'runtime_required': 'x86-64-v3',
                'enforcement': 'gnu-property-x86-isa-needed'}, 'entries': [
                    {'path': p, 'type': 'file', 'size': '1', 'sha256': '3' * 64}
                    for p in ('bin/memveil', 'bpf/probe.bpf.o', 'lib/memveil/libx.so.1', 'profiles/test.json')]},
            'files': {p: '3' * 64 for p in ('bin/memveil', 'bpf/probe.bpf.o',
                      'lib/memveil/libx.so.1', 'profiles/test.json', 'LICENSE')},
            'artifacts': [{'role': role, 'name': role + '.fixture', 'size': '1', 'sha256': '4' * 64}
                          for role in ('bundle', 'deb', 'rpm', 'source', 'sbom', 'provenance')]}


def test_manifest_seals_canonical_bytes_once(tmp_path):
    m = api()
    path = tmp_path / 'candidate.json'
    digest = m.seal_manifest(manifest(), path)
    assert digest == sha(path.read_bytes())
    assert path.read_bytes() == (json.dumps(manifest(), sort_keys=True, separators=(',', ':')) + '\n').encode()
    assert m.load_manifest(path, digest) == manifest()
    with pytest.raises(FileExistsError):
        m.seal_manifest(manifest(), path)
    path.write_text(json.dumps(manifest(), indent=2))
    with pytest.raises(ValueError, match='canonical'):
        m.load_manifest(path)


@pytest.mark.parametrize('damage', ['placeholder', 'duplicate', 'missing', 'extra', 'size', 'path', 'cpu', 'origin', 'toolchain'])
def test_manifest_rejects_incomplete_or_ambiguous_bindings(damage):
    m = api()
    doc = manifest()
    if damage == 'placeholder': doc['source']['commit'] = '0' * 40
    if damage == 'duplicate': doc['canonical_runtime']['entries'].append(doc['canonical_runtime']['entries'][0])
    if damage == 'missing': del doc['files']['bin/memveil']
    if damage == 'extra': doc['canonical_runtime']['entries'][0]['unknown'] = True
    if damage == 'size': doc['artifacts'][0]['size'] = 1
    if damage == 'path': doc['artifacts'][0]['name'] = '../escape'
    if damage == 'cpu': doc['canonical_runtime']['cpu']['runtime_required'] = 'x86-64-v2'
    if damage == 'origin': doc['origin'] = 'github-build'
    if damage == 'toolchain': del doc['toolchain']['pixi_lock_sha256']
    with pytest.raises(ValueError): m.validate_manifest(doc)


def test_loader_rejects_duplicate_json_keys(tmp_path):
    path = tmp_path / 'candidate.json'
    path.write_text('{"schema":"memveil-candidate/1","schema":"memveil-candidate/1"}\n')
    with pytest.raises(ValueError, match='duplicate'): api().load_manifest(path)


def test_safe_extract_refuses_links_duplicates_and_traversal(tmp_path):
    import io
    m = api()
    for kind in ('link', 'duplicate', 'escape'):
        archive = tmp_path / (kind + '.tar.gz')
        with tarfile.open(archive, 'w:gz') as stream:
            entry = tarfile.TarInfo('root/file' if kind != 'escape' else '../escape')
            if kind == 'link': entry.type, entry.linkname = tarfile.SYMTYPE, '/etc/passwd'
            stream.addfile(entry, io.BytesIO(b''))
            if kind == 'duplicate': stream.addfile(entry, io.BytesIO(b''))
        with pytest.raises(ValueError): m.extract_bundle(archive, tmp_path / kind)
    assert not (tmp_path.parent / 'escape').exists()


def test_evidence_exclusions_are_finite_and_cannot_hide_runtime(tmp_path):
    m = api()
    assert m.EVIDENCE_PATHS == frozenset({'packaging/tested-payload.sha256',
        'packaging/qualifications/candidate.json', 'packaging/qualifications/qualification.json',
        'packaging/qualifications/remote.json'})
    assert not m.evidence_path('packaging/qualifications/engine.so')
    assert not m.evidence_path('packaging/qualifications/nested/candidate.json')
    assert not m.evidence_path('tools/candidate.py')


def test_evidence_only_q_rejects_source_changes(tmp_path):
    m = api()
    subprocess.run(['git', 'init', '-q', str(tmp_path)], check=True)
    def commit():
        subprocess.run(['git', '-C', str(tmp_path), 'add', '.'], check=True)
        subprocess.run(['git', '-C', str(tmp_path), '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                        'commit', '-qm', 'Fixture'], check=True)
        return subprocess.check_output(['git', '-C', str(tmp_path), 'rev-parse', 'HEAD'], text=True).strip()
    (tmp_path / 'engine').write_text('source')
    c = commit()
    target = tmp_path / 'packaging/qualifications/qualification.json'
    target.parent.mkdir(parents=True)
    target.write_text('{}\n')
    q = commit()
    assert m.verify_q_diff(tmp_path, c, q) == ['packaging/qualifications/qualification.json']
    (tmp_path / 'engine').write_text('changed')
    bad = commit()
    with pytest.raises(ValueError, match='evidence-only'): m.verify_q_diff(tmp_path, c, bad)


def test_inventory_excludes_only_named_evidence_files(tmp_path):
    import source_inventory
    folder = tmp_path / 'packaging/qualifications'
    folder.mkdir(parents=True)
    (folder / 'qualification.json').write_text('{}\n')
    (folder / 'engine.so').write_bytes(b'\x7fELFsynthetic')
    (tmp_path / 'packaging/candidate-policy.json').write_text('{}\n')
    names = {e['path'] for e in source_inventory.take_inventory(tmp_path)['files']}
    assert 'packaging/qualifications/qualification.json' not in names
    assert 'packaging/qualifications/engine.so' in names
    assert 'packaging/candidate-policy.json' in names


def test_measurement_verdict_rederives_counts_and_rejects_skips():
    m = api()
    requirement = {'environment': 'ordinary-linux', 'predicates': {'events': 'equal', 'losses': 'zero'}}
    record = {'schema': 'memveil-gate-input/1', 'environment': 'ordinary-linux',
              'product': {'events': '10', 'losses': '0'}, 'oracle': {'events': '10', 'losses': '0'}}
    assert m.rederive_measurements(record, requirement)
    for side, key, value in [('product', 'events', '9'), ('oracle', 'events', '11'), ('product', 'losses', '1')]:
        bad = copy.deepcopy(record); bad[side][key] = value
        with pytest.raises(ValueError): m.rederive_measurements(bad, requirement)
    bad = copy.deepcopy(record); bad['status'] = 'PASS'
    with pytest.raises(ValueError): m.rederive_measurements(bad, requirement)
    bad = copy.deepcopy(record); bad['environment'] = 'snp'
    with pytest.raises(ValueError): m.rederive_measurements(bad, requirement)


def test_signed_inputs_need_pinned_trust_and_exact_subject(tmp_path):
    m = api()
    private, public = tmp_path / 'key', tmp_path / 'key.pub'
    subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(private)], check=True, capture_output=True)
    subject, signature = tmp_path / 'subject', tmp_path / 'subject.sig'
    subject.write_bytes(b'synthetic input only\n')
    subprocess.run(['ssh-keygen', '-Y', 'sign', '-f', str(private), '-n', 'memveil-candidate', str(subject)], check=True, capture_output=True)
    trusted = [sha(public.read_bytes())]
    m.verify_signature(subject, signature, public, trusted)
    with pytest.raises(ValueError, match='trust'): m.verify_signature(subject, signature, public, [])
    subject.write_bytes(b'substituted input\n')
    with pytest.raises(ValueError, match='signature'): m.verify_signature(subject, signature, public, trusted)


@pytest.mark.parametrize('args', [[], ['seal'], ['verify-bundle']])
def test_cli_help_is_available(args):
    result = subprocess.run([str(ROOT / 'tools/candidate'), *args, '--help'], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
