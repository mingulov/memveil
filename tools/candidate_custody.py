#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Explicitly armed import and promotion of qualified stored bytes.

Import fetches an exact draft asset set and re-verifies every
retained byte against the sealed candidate before writing the
custody statement. Dry-run and promote re-verify the stored bytes
from the retained artifact, check attestations, and validate the
proposed final tag; only promote publishes, and only onto a tag
that already exists and resolves to the candidate source commit.
All modes require CUSTODY_ARM=ARM-<MODE> plus an explicit
workflow_dispatch event. Qualification diffs run in the current
working directory, which must be the source checkout.

The payload closure runs through an explicit harness binary when
--harness-bin is given, else via cargo in the checkout under the
repository pin.
"""
import argparse
import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import tomllib
import zipfile

import candidate as c

PREDICATE = 'https://memveil.org/attestations/memveil-candidate-import/1'
REMOTE_CHECKS = {'tampered-payload/1': 'refusals',
                 'promotion-dry-run/1': 'verified_files',
                 'independent-attestation/1': 'verified_subjects',
                 'required-checks/1': 'enforced_checks',
                 'no-overwrite/1': 'preserved_assets'}


def decimal(value):
    c.require(isinstance(value, str)
              and re.fullmatch(r'[1-9][0-9]*', value),
              'invalid immutable remote ID')
    return value


def repository(value):
    c.require(isinstance(value, str)
              and re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',
                               value),
              'invalid repository')
    return value


class GitHub:
    """GitHub CLI transport; tests fake these methods, offline."""
    def json(self, path):
        return json.loads(subprocess.check_output(
            ['gh', 'api', '-H', 'X-GitHub-Api-Version: 2022-11-28',
             path]))

    def download(self, path, destination):
        with open(destination, 'xb') as stream:
            subprocess.run(
                ['gh', 'api', '-H',
                 'X-GitHub-Api-Version: 2022-11-28',
                 '-H', 'Accept: application/octet-stream', path],
                stdout=stream, check=True)


def get_holding_draft(api, repo, release_id, tag):
    """Fetch the holding draft release by its immutable ID.

    The record must carry the requested ID, still be a
    draft, and carry the expected candidate tag; a missing,
    published, or retagged record fails closed. Callers pass
    the recorded draft ID, never a listing lookup.
    """
    repository(repo); decimal(release_id)
    c.require(isinstance(tag, str) and tag,
              'invalid holding draft tag')
    release = api.json('repos/' + repo + '/releases/'
                       + release_id)
    c.require(isinstance(release, dict)
              and str(release.get('id')) == release_id
              and release.get('draft') is True
              and release.get('tag_name') == tag,
              'holding draft is missing, published, or '
              'retagged')
    return release


def download_draft_asset(api, repo, release, name, dest):
    """Download one uploaded draft asset by exact name.

    The asset must exist exactly once with state uploaded;
    the download goes by asset ID, never by tag. Returns
    the asset record; callers verify the bytes.
    """
    repository(repo)
    assets = release.get('assets')
    c.require(isinstance(assets, list),
              'draft assets are malformed')
    matches = [asset for asset in assets
               if isinstance(asset, dict)
               and asset.get('name') == name]
    c.require(len(matches) == 1,
              'draft asset is missing or ambiguous: ' + name)
    asset = matches[0]
    c.require(asset.get('state') == 'uploaded',
              'draft asset is not uploaded: ' + name)
    ident = decimal(str(asset.get('id')))
    api.download('repos/' + repo + '/releases/assets/' + ident,
                 dest)
    return asset


def import_assets(api, repo, release_id, asset_ids, manifest,
                  destination, extra=None):
    repository(repo); decimal(release_id)
    c.validate_manifest(manifest)
    records = manifest['artifacts'] + (extra or [])
    expected = {entry['name']: entry for entry in records}
    c.require(set(asset_ids) == set(expected)
              and len(set(asset_ids.values())) == len(asset_ids),
              'asset identity set differs')
    for ident in asset_ids.values(): decimal(ident)
    release = api.json('repos/' + repo + '/releases/' + release_id)
    c.require(str(release.get('id')) == release_id
              and release.get('draft') is True
              and re.fullmatch(r'candidate-[A-Za-z0-9._-]+',
                               release.get('tag_name', '')),
              'holding release must be a distinct draft candidate')
    assets = release.get('assets')
    c.require(isinstance(assets, list)
              and len(assets) == len(expected),
              'conflicting draft asset set')
    seen = set()
    for asset in assets:
        name = asset.get('name')
        c.require(name in expected and name not in seen
                  and str(asset.get('id')) == asset_ids[name],
                  'wrong or duplicate asset ID/name')
        seen.add(name)
        endpoint = 'repos/' + repo + '/releases/assets/' \
            + asset_ids[name]
        entry = expected[name]
        c.require(asset.get('url') == 'https://api.github.com/'
                  + endpoint
                  and asset.get('state') == 'uploaded',
                  'asset repository/state mismatch')
        c.require(str(asset.get('size')) == entry['size']
                  and asset.get('digest')
                  == 'sha256:' + entry['sha256'],
                  'asset digest or size mismatch')
    destination = Path(destination)
    destination.mkdir(mode=0o700)
    for name, entry in expected.items():
        api.download('repos/' + repo + '/releases/assets/'
                     + asset_ids[name], destination / name)
        c.verify_file(destination / name, entry)
    return {'schema': 'memveil-candidate-import/1',
            'operation': 'import', 'build_origin': 'local-build',
            'repository': repo, 'release_id': release_id,
            'assets': asset_ids,
            'candidate_sha256':
                c.digest_bytes(c.canonical(manifest)),
            'source_commit': manifest['source']['commit']}


def verify_remote_artifact(record, artifact_id, run_id, repo_id,
                           signer_commit, candidate_id, zip_digest):
    for value in (artifact_id, run_id, repo_id): decimal(value)
    c.hexid(signer_commit, 40); c.hexid(candidate_id)
    c.hexid(zip_digest)
    c.require(str(record.get('id')) == artifact_id
              and record.get('expired') is False
              and record.get('name') == 'candidate-' + candidate_id
              and record.get('digest') == 'sha256:' + zip_digest,
              'wrong or expired artifact')
    expiration = datetime.fromisoformat(
        record['expires_at'].replace('Z', '+00:00'))
    c.require(expiration > datetime.now(timezone.utc),
              'artifact expired')
    run = record.get('workflow_run', {})
    c.require(str(run.get('id')) == run_id
              and str(run.get('repository_id')) == repo_id
              and str(run.get('head_repository_id')) == repo_id
              and run.get('head_sha') == signer_commit,
              'artifact run/repository/source mismatch')


def extract_zip(archive, destination):
    destination = Path(destination)
    destination.mkdir(mode=0o700)
    with zipfile.ZipFile(archive) as stream:
        seen = set()
        for item in stream.infolist():
            name = c.relative(item.filename)
            c.require(name not in seen and not item.is_dir()
                      and '/' not in name
                      and (item.external_attr >> 16) & 0o170000
                      in (0, 0o100000),
                      'invalid stored artifact member')
            seen.add(name)
            c.write_once(destination / name, stream.read(item))
    return destination


def checked_git_file(root, commit, name, output):
    record = c.git(root, 'ls-tree', commit, '--', name).split()
    c.require(len(record) >= 4 and record[0] == '100644',
              'evidence file must be present non-executable '
              'regular data')
    data = subprocess.check_output(
        ['git', '-C', str(root), 'show', commit + ':' + name],
        env=c.git_env())
    c.write_once(output, data)


def verify_source(root, manifest):
    commit = manifest['source']['commit']
    c.require(c.git(root, 'rev-parse', commit + '^{tree}')
              == manifest['source']['tree'],
              'candidate source tree mismatch')
    locks = [('Cargo.lock', 'cargo_lock_sha256'),
             ('crates/ebpf/Cargo.lock', 'ebpf_lock_sha256')]
    for name, field in locks:
        data = subprocess.check_output(
            ['git', '-C', str(root), 'show', commit + ':' + name],
            env=c.git_env())
        c.require(c.digest_bytes(data)
                  == manifest['toolchain'][field],
                  'candidate toolchain/source mismatch')
    policy = subprocess.check_output(
        ['git', '-C', str(root), 'show',
         commit + ':packaging/candidate-policy.json'],
        env=c.git_env())
    c.require(c.digest_bytes(policy)
              == manifest['policy_sha256'],
              'candidate policy differs from C')


def verify_artifacts(root, manifest, directory, harness_bin=None):
    """Verify retained bytes, closure, source, SBOM and origin.

    Returns (paths, bundled): the role paths plus the already
    verified parsed bundle facts, so callers never re-read the
    bundle from disk after verification.
    """
    c.validate_manifest(manifest)
    directory = Path(directory)
    paths = {entry['role']: directory / entry['name']
             for entry in manifest['artifacts']}
    for entry in manifest['artifacts']:
        c.verify_file(directory / entry['name'], entry)
    with tempfile.TemporaryDirectory(
            prefix='candidate-verify-') as tmp:
        tmp = Path(tmp)
        extracted = c.safe_extract(paths['bundle'],
                                   tmp / 'bundle', True, False)
        bundled = c.verify_bundle_dir(extracted)
        commit = manifest['source']['commit']
        c.require(bundled['revision'] == commit,
                  'bundle revision differs from the source commit')
        tools = manifest['toolchain']['tools']
        c.require(bundled['cargo_version'] == tools['cargo']
                  and bundled['rustc_version'] == tools['rustc'],
                  'bundle toolchain record differs')
        linker = bundled['build_receipt']['tools']['bpf_linker']
        c.require(linker == tools['bpf_linker'],
                  'recorded bpf-linker differs from the sealed '
                  'toolchain')
        entries, inventory = c.git_inventory(root, commit)
        c.require(entries, 'empty source inventory')
        c.require(inventory
                  == manifest['source']['inventory_sha256'],
                  'candidate source tree mismatch')
        locks = c.verify_source_archive(paths['source'], entries)
        c.require(locks['cargo_lock_sha256']
                  == bundled['lock_sha256']
                  and locks['ebpf_lock_sha256']
                  == bundled['ebpf_lock_sha256'],
                  'source archive Cargo locks differ from the '
                  'bundle')
        closure = c.collect_payload_closure(
            root, harness_bin, paths['bundle'], paths['deb'],
            paths['rpm'])
        c.require(closure == c.expected_payload(manifest),
                  'package payload closure mismatch')
        recorded = bundled['build_receipt']
    verify_sbom(c.read_json(paths['sbom']), manifest)
    origin = c.read_json(paths['provenance'], sealed=True)
    subjects = {entry['name']: entry['sha256']
                for entry in manifest['artifacts']
                if entry['role'] != 'provenance'}
    c.verify_provenance(origin, manifest['source'],
                        manifest['toolchain'], manifest['files'],
                        subjects, recorded)
    return paths, bundled


def verify_sbom(sbom, manifest):
    """Verify the SBOM binds the full closure and the containers."""
    c.verify_sbom(sbom, manifest['files'], manifest['artifacts'])


def verify_release_version(tag, bundle_version, source_version,
                           claim):
    c.require(tag == 'v' + bundle_version
              and bundle_version == source_version,
              'final tag/product/source version mismatch')
    match = re.fullmatch(r'0\.([123])\.[0-9]+(?:-[A-Za-z0-9.-]+)?',
                         source_version)
    c.require(match is not None,
              'release version needs a separately reviewed claim '
              'policy')
    required = {'1': 'ordinary-preview', '2': 'snp-journal',
                '3': 'security-workflow'}[match.group(1)]
    c.require(claim == required,
              'release qualification claim is too weak or '
              'inconsistent')


def attest_verify(path, repo, signer):
    subprocess.run(
        ['gh', 'attestation', 'verify', str(path), '--repo', repo,
         '--signer-workflow',
         repo + '/.github/workflows/release.yml',
         '--signer-digest', signer, '--source-digest', signer,
         '--predicate-type', PREDICATE,
         '--deny-self-hosted-runners'], check=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',
                        choices=('import', 'promote', 'dry-run'))
    parser.add_argument('--request',
                        help='JSON request file; otherwise '
                        'CUSTODY_REQUEST environment')
    parser.add_argument('--out', required=True)
    parser.add_argument('--harness-bin', default=None,
                        help='release-entry harness binary; '
                        'otherwise cargo runs it in the checkout')
    args = parser.parse_args(argv)
    try:
        if args.request:
            request = c.read_json(args.request)
        else:
            request = json.loads(os.environ['CUSTODY_REQUEST'],
                                 object_pairs_hook=c.unique)
        run(args.mode, request, Path(args.out), args.harness_bin)
    except (OSError, ValueError, KeyError,
            subprocess.CalledProcessError,
            zipfile.BadZipFile) as error:
        parser.exit(1, 'candidate-custody: ' + str(error) + '\n')


def run(mode, request, out, harness_bin=None):
    c.require(os.environ.get('CUSTODY_ARM')
              == 'ARM-' + mode.upper(),
              'explicit custody arming required')
    c.require(os.environ.get('GITHUB_EVENT_NAME')
              == 'workflow_dispatch',
              'custody requires explicit dispatch')
    repo = repository(os.environ['GITHUB_REPOSITORY'])
    c.require(request['repository'] == repo,
              'request repository mismatch')
    root = Path.cwd()
    source = request['source_commit']
    qualification = request['qualification_commit']
    c.hexid(source, 40); c.hexid(qualification, 40)
    c.hexid(request['candidate_sha256'])
    c.verify_q_diff(source, qualification)
    c.verify_q_diff(source, os.environ['GITHUB_SHA'])
    c.require(c.git(root, 'rev-parse', 'HEAD')
              == os.environ['GITHUB_SHA'],
              'workflow checkout differs from trusted signer '
              'source')
    out = Path(out)
    out.mkdir(mode=0o700)
    checked_git_file(root, qualification,
                     'packaging/qualifications/candidate.json',
                     out / 'candidate.json')
    manifest = c.load_manifest(out / 'candidate.json',
                               request['candidate_sha256'])
    c.require(manifest['source']['commit'] == source,
              'request source mismatch')
    verify_source(root, manifest)
    checked_git_file(root, qualification,
                     'packaging/tested-payload.sha256',
                     out / 'TESTED-SHA256.txt')
    c.verify_tested_payload(manifest, out / 'TESTED-SHA256.txt')
    checked_git_file(root, source, 'packaging/candidate-policy.json',
                     out / 'policy.json')
    checked_git_file(root, qualification,
                     'packaging/qualifications/qualification.json',
                     out / 'qualification.json')
    q = c.read_json(out / 'qualification.json', sealed=True)
    archive_record = q['evidence_archive']
    c.exact(archive_record, {'name', 'size', 'sha256'},
            'evidence archive')
    c.require(archive_record['name']
              == 'qualification-evidence.tar.gz',
              'evidence archive name mismatch')
    c.parse_size(archive_record['size'])
    c.hexid(archive_record['sha256'])
    # The archive-digest record ships beside the archive as a
    # draft asset: pin the draft copy to the Q-committed
    # bytes, which the qualification step below re-verifies
    # over the stored evidence.
    qualification_record = {
        'name': 'qualification.json',
        'size': str((out / 'qualification.json').stat()
                    .st_size),
        'sha256': c.digest(out / 'qualification.json')}
    api = GitHub()
    if mode == 'import':
        custody = import_assets(
            api, repo, request['release_id'], request['asset_ids'],
            manifest, out / 'stored',
            [archive_record, qualification_record])
        stored = out / 'stored'
    else:
        checked_git_file(root, qualification,
                         'packaging/qualifications/remote.json',
                         out / 'remote.json')
        remote = c.read_json(out / 'remote.json', sealed=True)
        c.exact(remote, {'schema', 'candidate_sha256',
                         'source_commit', 'repository',
                         'repository_id', 'run_id', 'artifact_id',
                         'artifact_sha256', 'signer_commit',
                         'custody_sha256', 'checks'},
                'remote receipt')
        c.require(remote['schema'] == 'memveil-remote-custody/1'
                  and remote['candidate_sha256']
                  == request['candidate_sha256']
                  and remote['source_commit'] == source
                  and remote['repository'] == repo,
                  'remote custody subject mismatch')
        c.require(remote['run_id'] == request['run_id']
                  and remote['artifact_id']
                  == request['artifact_id'],
                  'dispatch immutable IDs differ')
        c.verify_q_diff(source, remote['signer_commit'])
        record = api.json('repos/' + repo + '/actions/artifacts/'
                          + decimal(remote['artifact_id']))
        verify_remote_artifact(
            record, remote['artifact_id'], remote['run_id'],
            remote['repository_id'], remote['signer_commit'],
            remote['candidate_sha256'], remote['artifact_sha256'])
        run_record = api.json('repos/' + repo + '/actions/runs/'
                              + remote['run_id'])
        c.require(run_record['status'] == 'completed'
                  and run_record['conclusion'] == 'success'
                  and run_record['event'] == 'workflow_dispatch'
                  and run_record['path']
                  == '.github/workflows/release.yml'
                  and run_record['head_sha']
                  == remote['signer_commit']
                  and str(run_record['repository']['id'])
                  == remote['repository_id'],
                  'import run did not succeed')
        api.download('repos/' + repo + '/actions/artifacts/'
                     + remote['artifact_id'] + '/zip',
                     out / 'stored.zip')
        c.require(c.digest(out / 'stored.zip')
                  == remote['artifact_sha256'],
                  'stored artifact ZIP differs')
        stored = extract_zip(out / 'stored.zip', out / 'stored')
        expected_names = {entry['name']
                          for entry in manifest['artifacts']} | {
                              archive_record['name'],
                              'qualification.json', 'custody.json'}
        c.require({path.name for path in stored.iterdir()}
                  == expected_names,
                  'stored artifact has missing or extra files')
        c.require(c.digest(stored / 'custody.json')
                  == remote['custody_sha256'],
                  'custody statement differs')
        custody = c.read_json(stored / 'custody.json', sealed=True)
        c.require(custody['schema']
                  == 'memveil-candidate-import/1'
                  and custody['operation'] == 'import'
                  and custody['build_origin'] == 'local-build'
                  and custody['source_commit'] == source
                  and custody['candidate_sha256']
                  == request['candidate_sha256']
                  and custody['repository'] == repo,
                  'untrusted custody origin/subject')
        subjects = [stored / entry['name']
                    for entry in manifest['artifacts']]
        for path in subjects + [stored / 'custody.json']:
            attest_verify(path, repo, remote['signer_commit'])

    c.verify_file(stored / archive_record['name'], archive_record)
    evidence = c.safe_extract(stored / archive_record['name'],
                              out / 'evidence', True, False)
    qualified = c.verify_qualification(
        out / 'candidate.json', out / 'qualification.json',
        out / 'policy.json', evidence, source_tree=root)
    paths, bundled = verify_artifacts(
        root, manifest, stored, harness_bin)
    expected_checksums = c.verify_signed_checksums(
        manifest, evidence, qualified['trusted_keys'])
    if mode == 'promote':
        verify_remote_checks(remote['checks'], api, repo, source,
                             request['candidate_sha256'],
                             qualified)
    if mode == 'import':
        c.write_once(stored / 'custody.json', c.canonical(custody))
        checksums = expected_checksums \
            + c.digest(stored / 'custody.json') + '  custody.json\n'
        c.write_once(out / 'SUBJECTS.txt', checksums.encode())
    else:
        tag = request['tag']
        version_source = subprocess.check_output(
            ['git', '-C', str(root), 'show',
             source + ':Cargo.toml'],
            env=c.git_env()).decode()
        version = tomllib.loads(version_source)['package'][
            'version']
        verify_release_version(tag, bundled['engine_version'],
                               version, qualified['claim'])
        c.require(re.fullmatch(
            r'v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?', tag),
            'invalid final tag')
        suffix = '^{commit}' if mode == 'promote' else ''
        probe = subprocess.run(
            ['git', '-C', str(root), 'rev-parse',
             'refs/tags/' + tag + suffix],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env=c.git_env())
        if mode == 'dry-run':
            c.require(probe.returncode != 0,
                      'final tag already exists; dry-run validates '
                      'the proposed tag before it is created')
        else:
            c.require(probe.returncode == 0
                      and probe.stdout.strip() == source,
                      'final tag must exist and point to C')
        # Read-only existence check before any release mutation;
        # all other errors fail closed.
        listing = api.json('repos/' + repo + '/releases?per_page=100')
        c.require(not any(item.get('tag_name') == tag
                          for item in listing),
                  'release already exists; overwrite refused')
        if mode == 'promote':
            # Notes come from the C blob (mode-pinned), never
            # the ambient worktree file a stray edit could swap.
            checked_git_file(root, source,
                             'docs/release-notes.md',
                             out / 'release-notes.md')
            command = ['gh', 'release', 'create', tag, '--repo',
                       repo, '--verify-tag', '--draft', '--title',
                       tag, '--notes-file',
                       str(out / 'release-notes.md')]
            if tag.startswith('v0.') or '-' in tag:
                command.append('--prerelease')
            subprocess.run(command, check=True)
            subprocess.run(['gh', 'release', 'upload', tag,
                            '--repo', repo,
                            *[str(p) for p in paths.values()]],
                           check=True)
            subprocess.run(['gh', 'release', 'edit', tag, '--repo',
                            repo, '--draft=false'], check=True)


def verify_remote_checks(checks, api, repo, source, candidate_id,
                         trust):
    c.exact(checks, REMOTE_CHECKS, 'required remote checks')
    for ident, binding in checks.items():
        c.exact(binding, {'check_id', 'run_id', 'head_sha',
                          'receipt', 'inputs', 'signature_base64',
                          'public_key'}, 'remote check binding')
        c.hexid(binding['head_sha'], 40)
        result = api.json('repos/' + repo + '/check-runs/'
                          + decimal(binding['check_id']))
        prefix = 'https://github.com/' + repo + '/actions/runs/' \
            + decimal(binding['run_id']) + '/job/'
        c.require(result.get('name') == ident
                  and result.get('status') == 'completed'
                  and result.get('conclusion') == 'success'
                  and result.get('head_sha')
                  == binding['head_sha']
                  and result.get('app', {}).get('slug')
                  == 'github-actions'
                  and result.get('details_url', '')
                  .startswith(prefix),
                  'required remote check failed or untrusted')
        doc = binding['receipt']
        c.exact(doc, {'schema', 'gate', 'candidate_sha256',
                      'source_commit', 'inputs_sha256'},
                'remote gate receipt')
        c.require(doc['schema'] == 'memveil-remote-gate/1'
                  and doc['gate'] == ident
                  and doc['candidate_sha256'] == candidate_id
                  and doc['source_commit'] == source,
                  'remote receipt subject differs')
        c.require(c.digest_bytes(c.canonical(binding['inputs']))
                  == c.hexid(doc['inputs_sha256']),
                  'remote oracle inputs differ')
        with tempfile.TemporaryDirectory(
                prefix='remote-receipt-') as tmp:
            tmp = Path(tmp)
            c.write_once(tmp / 'receipt', c.canonical(doc))
            c.write_once(tmp / 'signature',
                         base64.b64decode(
                             binding['signature_base64'],
                             validate=True))
            c.write_once(tmp / 'public',
                         binding['public_key'].encode())
            c.verify_signature(tmp / 'receipt', tmp / 'signature',
                               tmp / 'public',
                               trust['trusted_keys'])
        c.rederive_measurements(
            binding['inputs'], {'environment': 'offline',
                                'predicates':
                                    {REMOTE_CHECKS[ident]: 'equal',
                                     'failures': 'zero'}})


if __name__ == '__main__': main()
