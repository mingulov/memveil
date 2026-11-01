# SPDX-License-Identifier: GPL-3.0-or-later
"""Fake GitHub API transport tests; no network, credentials, refs or releases."""
import copy
import importlib.util
from pathlib import Path
import sys
import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from test_candidate import manifest, sha


def api():
    assert importlib.util.find_spec('candidate_custody'), 'custody protocol missing'
    import candidate_custody
    return candidate_custody


class FakeGitHub:
    def __init__(self, doc):
        self.calls = []
        self.data = {}
        assets = []
        for i, record in enumerate(doc['artifacts'], 100):
            record['size'] = '1'; record['sha256'] = sha(b'x')
            assets.append({'id': i, 'name': record['name'], 'size': 1, 'state': 'uploaded',
                           'digest': 'sha256:' + sha(b'x'), 'url': 'https://api.github.com/repos/example/project/releases/assets/' + str(i)})
            self.data['repos/example/project/releases/assets/' + str(i)] = b'x'
        self.release = {'id': 1, 'draft': True, 'tag_name': 'candidate-fixture', 'assets': assets}
    def json(self, path):
        self.calls.append(('GET', path))
        assert path == 'repos/example/project/releases/1'
        return copy.deepcopy(self.release)
    def download(self, path, destination):
        self.calls.append(('DOWNLOAD', path))
        Path(destination).write_bytes(self.data[path])


def test_import_downloads_only_explicit_immutable_same_repo_assets(tmp_path):
    m = api(); doc = manifest(); remote = FakeGitHub(doc)
    ids = {a['name']: str(a['id']) for a in remote.release['assets']}
    result = m.import_assets(remote, 'example/project', '1', ids, doc, tmp_path / 'import')
    assert result['operation'] == 'import' and result['build_origin'] == 'local-build'
    assert result['assets'] == ids
    assert len(remote.calls) == 7
    assert all((tmp_path / 'import' / a['name']).read_bytes() == b'x' for a in doc['artifacts'])
    with pytest.raises(FileExistsError): m.import_assets(remote, 'example/project', '1', ids, doc, tmp_path / 'import')


@pytest.mark.parametrize('damage', ['wrong-id', 'wrong-repository', 'not-draft', 'duplicate', 'extra', 'substitute', 'wrong-digest'])
def test_import_rejects_conflicting_custody(tmp_path, damage):
    m = api(); doc = manifest(); remote = FakeGitHub(doc)
    ids = {a['name']: str(a['id']) for a in remote.release['assets']}
    if damage == 'wrong-id': ids[doc['artifacts'][0]['name']] = '999'
    if damage == 'wrong-repository': remote.release['assets'][0]['url'] = 'https://api.github.com/repos/other/project/releases/assets/100'
    if damage == 'not-draft': remote.release['draft'] = False
    if damage == 'duplicate': remote.release['assets'].append(remote.release['assets'][0])
    if damage == 'extra': remote.release['assets'].append(dict(remote.release['assets'][0], id=999, name='extra'))
    if damage == 'substitute': remote.data['repos/example/project/releases/assets/100'] = b'y'
    if damage == 'wrong-digest': remote.release['assets'][0]['digest'] = 'sha256:' + '0' * 64
    with pytest.raises(ValueError): m.import_assets(remote, 'example/project', '1', ids, doc, tmp_path / 'import')


def test_remote_artifact_refuses_expiry_wrong_run_and_forks():
    m = api()
    record = {'id': 7, 'expired': False, 'name': 'candidate-' + 'a'*64, 'digest': 'sha256:' + 'b'*64,
              'expires_at': '2099-01-01T00:00:00Z', 'workflow_run': {'id': 8, 'repository_id': 9,
              'head_repository_id': 9, 'head_sha': 'c'*40}}
    m.verify_remote_artifact(record, '7', '8', '9', 'c'*40, 'a'*64, 'b'*64)
    for key, value in [('expired', True), ('id', 10), ('expires_at', '2000-01-01T00:00:00Z')]:
        bad = copy.deepcopy(record); bad[key] = value
        with pytest.raises(ValueError): m.verify_remote_artifact(bad, '7', '8', '9', 'c'*40, 'a'*64, 'b'*64)
    bad = copy.deepcopy(record); bad['workflow_run']['head_repository_id'] = 10
    with pytest.raises(ValueError): m.verify_remote_artifact(bad, '7', '8', '9', 'c'*40, 'a'*64, 'b'*64)


def test_tags_cannot_build_or_publish_and_dispatch_is_armed():
    text = (ROOT / '.github/workflows/release.yml').read_text()
    assert '\n  push:' not in text
    assert 'tools/build' not in text and 'tools/package' not in text
    assert 'workflow_dispatch:' in text
    assert 'candidate-custody' in text and 'ARM' in text
    assert 'attest-build-provenance' not in text
    assert 'memveil-candidate-import/1' in text
    assert 'retention-days: 90' in text


def test_unarmed_custody_has_no_side_effects(tmp_path, monkeypatch):
    monkeypatch.delenv('CUSTODY_ARM', raising=False)
    with pytest.raises(ValueError, match='arming'):
        api().run('import', {}, tmp_path / 'out')
    assert not (tmp_path / 'out').exists()


def test_remote_checks_need_signed_independent_counts(tmp_path):
    import base64
    import subprocess
    import candidate as c
    m = api()
    key = tmp_path / 'key'
    subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True)
    public = (tmp_path / 'key.pub').read_text()
    policy = {'trusted_keys': [sha(public.encode())]}
    checks = {}
    predicates = {'tampered-payload/1': 'refusals', 'promotion-dry-run/1': 'verified_files',
                  'independent-attestation/1': 'verified_subjects', 'required-checks/1': 'enforced_checks',
                  'no-overwrite/1': 'preserved_assets'}
    for i, (ident, measurement) in enumerate(predicates.items(), 1):
        inputs = {'schema': 'memveil-gate-input/1', 'environment': 'offline',
                  'product': {measurement: '2', 'failures': '0'}, 'oracle': {measurement: '2', 'failures': '0'}}
        receipt = {'schema': 'memveil-remote-gate/1', 'gate': ident, 'candidate_sha256': 'a'*64,
                   'source_commit': 'b'*40, 'inputs_sha256': sha(c.canonical(inputs))}
        file = tmp_path / str(i); file.write_bytes(c.canonical(receipt))
        subprocess.run(['ssh-keygen', '-Y', 'sign', '-f', str(key), '-n', 'memveil-candidate', str(file)], check=True, capture_output=True)
        checks[ident] = {'check_id': str(i), 'run_id': '9', 'head_sha': 'b'*40, 'receipt': receipt, 'inputs': inputs,
                         'signature_base64': base64.b64encode(Path(str(file)+'.sig').read_bytes()).decode(), 'public_key': public}
    class FakeChecks:
        def json(self, path):
            i = int(path.rsplit('/', 1)[1])
            return {'name': list(predicates)[i-1], 'status': 'completed', 'conclusion': 'success',
                    'head_sha': 'b'*40, 'app': {'slug': 'github-actions'},
                    'details_url': 'https://github.com/example/project/actions/runs/9/job/123'}
    m.verify_remote_checks(checks, FakeChecks(), 'example/project', 'b'*40, 'a'*64, policy)
    changed = copy.deepcopy(checks)
    changed['tampered-payload/1']['inputs']['product']['refusals'] = '0'
    with pytest.raises(ValueError, match='inputs differ'):
        m.verify_remote_checks(changed, FakeChecks(), 'example/project', 'b'*40, 'a'*64, policy)
    with pytest.raises(ValueError, match='untrusted'):
        m.verify_remote_checks(checks, FakeChecks(), 'example/project', 'b'*40, 'a'*64, {'trusted_keys': []})


def sbom_fixture(doc):
    import candidate as c
    return {'spdxVersion': 'SPDX-2.3', 'files': [{'fileName': 'payload/' + name,
        'checksums': [{'algorithm': 'SHA256', 'checksumValue': value}]} for name, value in c.expected_payload(doc).items()],
        'packages': [{'name': entry['name'], 'checksums': [{'algorithm': 'SHA256', 'checksumValue': entry['sha256']}]} for entry in doc['artifacts'] if entry['role'] in ('bundle', 'deb', 'rpm')]}


def test_sbom_requires_exact_payload_and_container_subjects():
    m = api(); doc = manifest()
    assert hasattr(m, 'verify_sbom'), 'SBOM closure is not independently checked'
    sbom = sbom_fixture(doc)
    m.verify_sbom(sbom, doc)
    for damage in ('extra', 'missing', 'duplicate', 'container'):
        bad = copy.deepcopy(sbom)
        if damage == 'extra': bad['files'].append({'fileName': 'payload/bundle/evil.so', 'checksums': [{'algorithm': 'SHA256', 'checksumValue': '9'*64}]})
        if damage == 'missing': bad['files'].pop()
        if damage == 'duplicate': bad['files'].append(bad['files'][0])
        if damage == 'container': bad['packages'][0]['checksums'][0]['checksumValue'] = '9'*64
        with pytest.raises(ValueError): m.verify_sbom(bad, doc)


def test_release_version_cannot_promote_older_bytes_or_weaker_claims():
    m = api()
    assert hasattr(m, 'verify_release_version'), 'release version/claim binding missing'
    for version, claim in [('0.1.1', 'ordinary-preview'), ('0.2.0', 'snp-journal'), ('0.3.0', 'security-workflow')]:
        m.verify_release_version('v' + version, version, version, claim)
    for tag, binary, source, claim in [('v0.1.1', '0.1.0', '0.1.0', 'ordinary-preview'),
            ('v0.2.0', '0.2.0', '0.2.0', 'ordinary-preview'),
            ('v0.3.0', '0.3.0', '0.3.0', 'snp-journal'),
            ('v0.1.1', '0.1.1', '0.1.0', 'ordinary-preview')]:
        with pytest.raises(ValueError): m.verify_release_version(tag, binary, source, claim)
