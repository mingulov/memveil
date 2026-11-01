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


def test_candidate_payload_uses_full_closure_and_installed_paths():
    doc = manifest()
    assert len(api().expected_payload(doc)) == 3 * len(doc['files'])
    assert api().expected_payload(doc)['bundle/lib/memveil/libx.so.1'] == '3' * 64
    assert api().expected_payload(doc)['deb/usr/share/doc/memveil/LICENSE'] == '3' * 64


def test_payload_check_candidate_refuses_matching_but_incomplete_manifests(tmp_path):
    m = api(); doc = manifest()
    candidate = tmp_path / 'candidate.json'; m.seal_manifest(doc, candidate)
    payload = tmp_path / 'payload.txt'
    entries = m.expected_payload(doc)
    entries.pop('bundle/LICENSE')
    payload.write_text(''.join(v + '  ' + k + '\n' for k, v in sorted(entries.items())))
    result = subprocess.run([str(ROOT / 'tools/payload-gate'), '--check', '--candidate', str(candidate),
        '--packaged', str(payload), '--tested', str(payload)], capture_output=True, text=True)
    assert result.returncode == 1 and 'candidate' in result.stderr, result.stderr


def qualification_fixture(tmp_path):
    m = api()
    key = tmp_path / 'key'
    subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True)
    policy = {'schema': 'memveil-candidate-policy/1', 'claim': 'ordinary-preview', 'retention_days': '90',
              'trusted_keys': [sha((tmp_path / 'key.pub').read_bytes())],
              'required_gates': {'synthetic-counts/1': {'environment': 'offline', 'predicates': {'events': 'equal', 'losses': 'zero'}}}}
    policy_path = tmp_path / 'policy.json'; policy_path.write_bytes(m.canonical(policy))
    doc = manifest(); doc['policy_sha256'] = sha(policy_path.read_bytes())
    candidate_path = tmp_path / 'candidate.json'; candidate_id = m.seal_manifest(doc, candidate_path)
    inputs = {'schema': 'memveil-gate-input/1', 'environment': 'offline',
              'product': {'events': '12', 'losses': '0'}, 'oracle': {'events': '12', 'losses': '0'}}
    inputs['sources'] = {}
    for side in ('product', 'oracle'):
        raw = tmp_path / (side + '.json'); raw.write_bytes(m.canonical(inputs[side]))
        inputs['sources'][side] = {name: {'file': raw.name, 'sha256': sha(raw.read_bytes()), 'path': [name], 'encoding': 'u64'}
                                  for name in inputs[side]}
    input_path = tmp_path / 'input.json'; input_path.write_bytes(m.canonical(inputs))
    receipt = {'schema': 'memveil-gate-receipt/1', 'gate': 'synthetic-counts/1', 'candidate_sha256': candidate_id,
               'source_commit': doc['source']['commit'], 'inputs': 'input.json', 'inputs_sha256': sha(input_path.read_bytes())}
    receipt_path = tmp_path / 'receipt.json'; receipt_path.write_bytes(m.canonical(receipt))
    subprocess.run(['ssh-keygen', '-Y', 'sign', '-f', str(key), '-n', 'memveil-candidate', str(receipt_path)], check=True, capture_output=True)
    q = {'schema': 'memveil-qualification/1', 'candidate_sha256': candidate_id, 'source_commit': doc['source']['commit'],
         'claim': 'ordinary-preview', 'evidence_archive': {'name': 'qualification-evidence.tar.gz', 'size': '1', 'sha256': '5' * 64},
         'gates': {'synthetic-counts/1': {'receipt': 'receipt.json', 'receipt_sha256': sha(receipt_path.read_bytes()),
                   'signature': 'receipt.json.sig', 'public_key': 'key.pub'}}}
    q_path = tmp_path / 'qualification.json'; q_path.write_bytes(m.canonical(q))
    return candidate_path, q_path, policy_path, q, inputs


def test_qualification_requires_signed_exact_inputs_with_no_remote_ids(tmp_path):
    m = api(); manifest_path, q_path, policy, q, inputs = qualification_fixture(tmp_path)
    assert m.verify_qualification(manifest_path, q_path, policy, tmp_path) == q
    assert not any('remote' in key for key in q)
    inputs['oracle']['events'] = '13'
    (tmp_path / 'input.json').write_bytes(m.canonical(inputs))
    with pytest.raises(ValueError, match='inputs changed'): m.verify_qualification(manifest_path, q_path, policy, tmp_path)


@pytest.mark.parametrize('damage', ['skip', 'source', 'candidate', 'extra', 'signature'])
def test_qualification_fails_closed(tmp_path, damage):
    m = api(); manifest_path, q_path, policy, q, _ = qualification_fixture(tmp_path)
    if damage == 'skip': q['gates'] = {}
    if damage == 'source': q['source_commit'] = '9' * 40
    if damage == 'candidate': q['candidate_sha256'] = '9' * 64
    if damage == 'extra': q['status'] = 'PASS'
    if damage == 'signature': (tmp_path / 'receipt.json.sig').write_text('invalid')
    q_path.write_bytes(m.canonical(q))
    with pytest.raises(ValueError): m.verify_qualification(manifest_path, q_path, policy, tmp_path)


def test_bundle_inventory_digest_and_toolchain_are_rederived():
    import source_inventory
    assert hasattr(api(), 'verify_source_inventory'), 'bundle source inventory is only self-declared'
    entries = [{'path': name, 'kind': 'file', 'mode': '0o644', 'size': 1, 'sha256': value,
                'mtime_ns': 1, 'ctime_ns': 1} for name, value in [('pixi.lock', 'e'*64), ('toolchain.lock.json', 'd'*64)]]
    serialized = b''.join((json.dumps({k: v for k, v in entry.items() if k not in ('mtime_ns', 'ctime_ns')}, sort_keys=True, separators=(',', ':')) + '\n').encode() for entry in entries)
    doc = manifest(); doc['source']['inventory_sha256'] = sha(serialized)
    bundled = {'source_inventory': entries, 'source_inventory_digest': sha(serialized)}
    api().verify_source_inventory(doc, bundled)
    for damage in ('hash', 'lock', 'missing', 'duplicate'):
        bad = copy.deepcopy(bundled)
        if damage == 'hash': bad['source_inventory_digest'] = '8'*64
        if damage == 'lock': bad['source_inventory'][1]['sha256'] = '9'*64
        if damage == 'missing': bad.pop('source_inventory')
        if damage == 'duplicate': bad['source_inventory'].append(bad['source_inventory'][0])
        with pytest.raises(ValueError): api().verify_source_inventory(doc, bad)


def test_paced_read_oracle_cannot_pass_event_counts_alone():
    m = api()
    requirement = {'environment': 'offline', 'adapter': 'paced-replay/1',
        'predicates': {'events': 'equal', 'read_bytes': 'equal', 'read_calls': 'at-least',
            'device': 'equal', 'inode': 'equal', 'eof': 'equal', 'max_request_bytes': 'at-most',
            'duration_ns': 'at-least', 'wall_ns': 'at-least', 'rss_bytes': 'at-most', 'failures': 'zero'},
        'limits': {'events': '600000', 'eof': '1', 'max_request_bytes': '65536',
                   'duration_ns': '60000000000', 'wall_ns': '60000000000', 'rss_bytes': '268435456'}}
    actual = {'events': '600000', 'read_bytes': '65537', 'read_calls': '3', 'device': '1', 'inode': '42',
              'eof': '1', 'max_request_bytes': '65536', 'duration_ns': '60000000000',
              'wall_ns': '60000000000', 'rss_bytes': '1024', 'failures': '0'}
    expected = dict(actual, rss_bytes='268435456')
    record = {'schema': 'memveil-gate-input/1', 'environment': 'offline', 'product': actual, 'oracle': expected}
    assert m.rederive_measurements(record, requirement)
    bad = copy.deepcopy(record); bad['product']['read_calls'] = bad['oracle']['read_calls'] = '1'
    with pytest.raises(ValueError, match='read'): m.rederive_measurements(bad, requirement)
    bad = copy.deepcopy(record); bad['product']['rss_bytes'] = '0'
    with pytest.raises(ValueError, match='RSS'): m.rederive_measurements(bad, requirement)
    for name in ('events', 'duration_ns', 'wall_ns'):
        bad = copy.deepcopy(record); bad['product'][name] = bad['oracle'][name] = '1'
        with pytest.raises(ValueError): m.rederive_measurements(bad, requirement)


@pytest.mark.parametrize('field', ['lock_sha256', 'pixi_lock_sha256'])
def test_changed_candidate_toolchain_refuses_actual_bundle(tmp_path, field):
    # The independent loader fixture uses real ELF bytes and a sealed source inventory.
    sys.path.insert(0, str(ROOT / 'tests'))
    from support.test_candidate_input import sealed
    env = sealed.__wrapped__(tmp_path)
    m = api(); doc = m.load_manifest(env['MV_CANDIDATE_MANIFEST'])
    doc['toolchain'][field] = '9' * 64
    with pytest.raises(ValueError, match='toolchain differs'):
        m.verify_bundle(doc, env['MV_BUNDLE_TARBALL'], tmp_path / 'changed-toolchain')


def test_default_policy_preserves_qualification_budgets_and_missing_trust():
    m = api(); policy = m.validate_policy(m.read_json(ROOT / 'packaging/candidate-policy.json'))
    gates = policy['required_gates']
    assert gates['offline-replay/1']['limits']['events'] == '600000'
    assert gates['offline-replay/1']['limits']['duration_ns'] == '60000000000'
    assert gates['offline-replay/1']['limits']['rss_bytes'] == '268435456'
    assert gates['live-soak/1']['limits'] == {'duration_seconds': '4201', 'mixed_duration_seconds': '1800'}
    assert gates['region-replay/1']['limits'] == {'segments': '65536', 'duration_milliseconds': '60000'}
    assert gates['summary-overhead/1']['limits']['throughput_decrease_ppm'] == '50000'
    assert gates['summary-overhead/1']['limits']['p99_increase_ppm'] == '100000'
    assert m.EVIDENCE_VERSION == 'memveil-evidence-exclusions/1'


def test_signed_measurements_must_match_retained_raw_sources(tmp_path):
    m = api()
    assert hasattr(m, 'verify_measurement_sources'), 'raw measurements are not re-derived'
    raw = tmp_path / 'raw.json'; raw.write_text('{"events":12,"eof":true}\n')
    inputs = {'schema': 'memveil-gate-input/1', 'environment': 'offline',
              'product': {'events': '12', 'eof': '1'}, 'oracle': {'events': '12', 'eof': '1'}, 'sources': {}}
    for side in ('product', 'oracle'):
        side_raw = tmp_path / (side + '.json'); side_raw.write_bytes(raw.read_bytes())
        inputs['sources'][side] = {key: {'file': side_raw.name, 'sha256': sha(side_raw.read_bytes()),
            'path': [key], 'encoding': 'boolean' if key == 'eof' else 'u64'} for key in inputs[side]}
    m.verify_measurement_sources(inputs, tmp_path)
    inputs['product']['events'] = '13'
    with pytest.raises(ValueError, match='retained measurement'):
        m.verify_measurement_sources(inputs, tmp_path)


def test_qualified_export_requires_the_actual_archives(tmp_path):
    m = api(); manifest_path, q_path, policy, _, _ = qualification_fixture(tmp_path)
    assert hasattr(m, 'qualify_candidate'), 'tested export does not verify actual artifacts'
    output = tmp_path / 'tested.txt'
    with pytest.raises(ValueError, match='artifact must be a regular file'):
        m.qualify_candidate(tmp_path, manifest_path, q_path, policy, tmp_path / 'missing-evidence.tar.gz', tmp_path / 'lock', output)
    assert not output.exists()


def test_q_tested_payload_cannot_keep_placeholders_or_omit_files(tmp_path):
    m = api(); doc = manifest()
    assert hasattr(m, 'verify_tested_payload'), 'Q tested payload is not enforced'
    with pytest.raises(ValueError, match='placeholder'):
        m.verify_tested_payload(doc, ROOT / 'packaging/tested-payload.sha256')
    entries = m.expected_payload(doc)
    path = tmp_path / 'tested'
    path.write_text(''.join(value + '  ' + name + '\n' for name, value in sorted(entries.items())))
    m.verify_tested_payload(doc, path)
    path.write_text(path.read_text().split('\n', 1)[1])
    with pytest.raises(ValueError, match='closure'): m.verify_tested_payload(doc, path)


def test_signed_checksums_bind_every_candidate_artifact(tmp_path):
    m = api(); doc = manifest()
    key = tmp_path / 'key'
    subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True)
    (tmp_path / 'signer.pub').write_bytes((tmp_path / 'key.pub').read_bytes())
    sums = tmp_path / 'SHA256SUMS.txt'
    sums.write_text(''.join(e['sha256'] + '  ' + e['name'] + '\n' for e in sorted(doc['artifacts'], key=lambda x: x['name'])))
    subprocess.run(['ssh-keygen', '-Y', 'sign', '-f', str(key), '-n', 'memveil-candidate', str(sums)], check=True, capture_output=True)
    trusted = [sha((tmp_path / 'signer.pub').read_bytes())]
    assert hasattr(m, 'verify_signed_checksums'), 'local qualification lacks signed checksums'
    assert m.verify_signed_checksums(doc, tmp_path, trusted) == sums.read_text()
    doc['artifacts'][0]['sha256'] = '9' * 64
    with pytest.raises(ValueError, match='checksums differ'): m.verify_signed_checksums(doc, tmp_path, trusted)
