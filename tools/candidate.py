#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Immutable local candidates and evidence-only qualification boundaries."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile

import canonical_runtime as runtime

SCHEMA = 'memveil-candidate/1'
EVIDENCE_VERSION = 'memveil-evidence-exclusions/1'
EVIDENCE_PATHS = frozenset({'packaging/tested-payload.sha256',
    'packaging/qualifications/candidate.json', 'packaging/qualifications/qualification.json',
    'packaging/qualifications/remote.json'})
ROLES = frozenset({'bundle', 'deb', 'rpm', 'source', 'sbom', 'provenance'})
DOCUMENT_LIMIT = 16 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def exact(value, keys, label):
    require(isinstance(value, dict) and set(value) == set(keys), label + ' has invalid fields')


def hexid(value, width=64):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{%d}' % width, value)
            and value != '0' * width, 'invalid or placeholder identity')
    return value


def relative(value):
    require(isinstance(value, str) and value and '\\' not in value and
            all(part not in ('', '.', '..') for part in value.split('/')) and
            not any(ord(char) < 33 or ord(char) > 126 for char in value), 'invalid relative path')
    return value


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode()


def digest_bytes(value):
    return hashlib.sha256(value).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key: ' + key)
        result[key] = value
    return result


def read_regular(path, limit=DOCUMENT_LIMIT):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= limit, 'invalid or oversized regular file')
        value = stream.read(limit + 1)
    require(len(value) <= limit, 'oversized document')
    return value


def read_json(path, sealed=False):
    data = read_regular(path)
    try:
        value = json.loads(data, object_pairs_hook=unique, parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))
    except (RecursionError, UnicodeError) as error:
        raise ValueError('invalid JSON document') from error
    def depth(item, level=0):
        require(level <= 64, 'document nesting exceeds limit')
        if isinstance(item, dict):
            for child in item.values(): depth(child, level + 1)
        elif isinstance(item, list):
            for child in item: depth(child, level + 1)
    depth(value)
    if sealed:
        require(data == canonical(value), 'document bytes are not canonical')
    return value


def evidence_path(path):
    return path in EVIDENCE_PATHS


def validate_manifest(doc):
    exact(doc, {'schema', 'origin', 'source', 'toolchain', 'build_receipt_sha256',
                'bundle_manifest_sha256', 'policy_sha256', 'canonical_runtime', 'files', 'artifacts'}, 'candidate')
    require(doc['schema'] == SCHEMA and doc['origin'] == 'local-build', 'candidate requires truthful local build origin')
    exact(doc['source'], {'commit', 'tree', 'inventory_sha256'}, 'source')
    for key in ('commit', 'tree'): hexid(doc['source'][key], 40)
    hexid(doc['source']['inventory_sha256'])
    exact(doc['toolchain'], {'lock_sha256', 'pixi_lock_sha256'}, 'toolchain')
    for value in doc['toolchain'].values(): hexid(value)
    for key in ('build_receipt_sha256', 'bundle_manifest_sha256', 'policy_sha256'): hexid(doc[key])
    rt = doc['canonical_runtime']
    exact(rt, {'format', 'cpu', 'entries'}, 'runtime')
    require(rt['format'] == runtime.FORMAT and rt['cpu'] == runtime.runtime_cpu.CONTRACT, 'runtime CPU/format mismatch')
    require(isinstance(rt['entries'], list) and rt['entries'], 'empty runtime')
    names = []
    require(isinstance(doc['files'], dict) and doc['files'], 'empty full file closure')
    for name, value in doc['files'].items():
        relative(name)
        require(name != 'MANIFEST.json' and not evidence_path(name), 'invalid copied file')
        hexid(value)
    for entry in rt['entries']:
        exact(entry, {'type', 'path', 'size', 'sha256'}, 'runtime entry')
        require(entry['type'] == 'file', 'unsupported runtime entry type')
        name = relative(entry['path'])
        runtime.installed_path(name)
        runtime.parse_size(entry['size'])
        hexid(entry['sha256'])
        require(doc['files'].get(name) == entry['sha256'], 'runtime differs from full file closure')
        names.append(name)
    require(names == sorted(set(names)), 'runtime entries must be unique and sorted')
    require('bin/memveil' in names and all(any(n.startswith(p) for n in names)
            for p in ('lib/memveil/', 'bpf/', 'profiles/')), 'missing required runtime component')
    require(isinstance(doc['artifacts'], list), 'invalid artifacts')
    roles, names = [], []
    for entry in doc['artifacts']:
        exact(entry, {'role', 'name', 'size', 'sha256'}, 'artifact')
        require(entry['role'] in ROLES, 'unknown artifact role')
        require('/' not in relative(entry['name']), 'artifact name must be a basename')
        runtime.parse_size(entry['size'])
        hexid(entry['sha256'])
        roles.append(entry['role']); names.append(entry['name'])
    require(set(roles) == ROLES and len(roles) == len(ROLES) and len(set(names)) == len(names),
            'missing or duplicate artifact')
    return doc


def load_manifest(path, expected_digest=None):
    data = read_regular(path)
    if expected_digest is not None:
        require(digest_bytes(data) == hexid(expected_digest), 'candidate digest mismatch')
    doc = read_json(path, sealed=True)
    require(data == canonical(doc), 'candidate changed during reading')
    return validate_manifest(doc)


def write_once(path, data):
    with open(path, 'xb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def seal_manifest(doc, path):
    validate_manifest(doc)
    data = canonical(doc)
    write_once(path, data)
    return digest_bytes(data)


def artifact(doc, role):
    return next(entry for entry in doc['artifacts'] if entry['role'] == role)


def verify_file(path, entry):
    path = Path(path)
    require(not path.is_symlink() and path.is_file(), 'artifact must be a regular file')
    require(str(path.stat().st_size) == entry['size'] and runtime.digest(path) == entry['sha256'], 'artifact size/hash mismatch: ' + entry['name'])


def extract_bundle(archive, destination):
    """Extract a unique regular-file tar into a newly created directory."""
    destination = Path(destination)
    destination.mkdir(mode=0o700)
    with tarfile.open(archive, 'r:gz') as stream:
        members = stream.getmembers()
        names = set()
        require(members and len(members) <= 100000, 'invalid archive member count')
        total = 0
        for entry in members:
            name = relative(entry.name.rstrip('/') if entry.isdir() else entry.name)
            require(name not in names, 'duplicate archive member')
            require(entry.isfile() or entry.isdir(), 'archive links and special files are forbidden')
            require(not entry.mode & 0o7000, 'archive special permission bits forbidden')
            names.add(name)
            total += entry.size
            require(total <= 8 * 1024 ** 3, 'archive exceeds extraction limit')
        tops = {name.split('/')[0] for name in names}
        require(len(tops) == 1 and any('/' in name for name in names), 'archive requires one root')
        for entry in members:
            path = destination / entry.name
            if entry.isdir():
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                with stream.extractfile(entry) as source, open(path, 'xb') as target:
                    shutil.copyfileobj(source, target)
                path.chmod(entry.mode & 0o777)
    return destination / next(iter(tops))


def verify_source_inventory(manifest, bundled):
    import source_inventory
    entries = bundled.get('source_inventory')
    require(isinstance(entries, list) and entries, 'bundle lacks source inventory')
    names = []
    for entry in entries:
        require(isinstance(entry, dict), 'invalid source inventory entry')
        name = relative(entry.get('path'))
        names.append(name)
        require(entry.get('kind') in ('file', 'dir'), 'unsupported source inventory type')
        require(isinstance(entry.get('mode'), str) and re.fullmatch(r'0o[0-7]{3,4}', entry['mode']), 'invalid source mode')
        if entry['kind'] == 'file':
            exact(entry, {'path', 'kind', 'mode', 'size', 'sha256', 'mtime_ns', 'ctime_ns'}, 'source file')
            require(type(entry['size']) is int and 0 <= entry['size'] <= 18446744073709551615, 'invalid source size')
            hexid(entry['sha256'])
        else:
            exact(entry, {'path', 'kind', 'mode'}, 'source directory')
    require(names == sorted(set(names)), 'duplicate or unsorted source inventory')
    digest = source_inventory.inventory_digest(entries)
    require(digest == bundled.get('source_inventory_digest') == manifest['source']['inventory_sha256'], 'source inventory digest differs')
    files = {entry['path']: entry.get('sha256') for entry in entries}
    for name, field in [('toolchain.lock.json', 'lock_sha256'), ('pixi.lock', 'pixi_lock_sha256')]:
        require(files.get(name) == manifest['toolchain'][field], 'bundle source toolchain differs')


def verify_bundle(manifest, bundle_path, destination):
    """Verify exact candidate archive and full runtime closure; never build."""
    validate_manifest(manifest)
    verify_file(bundle_path, artifact(manifest, 'bundle'))
    root = extract_bundle(bundle_path, destination)
    require(runtime.digest(root / 'MANIFEST.json') == manifest['bundle_manifest_sha256'], 'bundle manifest differs')
    bundled = runtime.verify_bundle(root)
    verify_source_inventory(manifest, bundled)
    require(bundled['canonical_runtime'] == manifest['canonical_runtime'] and bundled['files'] == manifest['files'], 'bundle closure differs')
    require(bundled['memveil_revision'] == manifest['source']['commit'] and
            bundled['source_inventory_digest'] == manifest['source']['inventory_sha256'] and
            bundled['build_receipt_sha256'] == manifest['build_receipt_sha256'], 'bundle source/build differs')
    return root


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args], text=True).strip()


def verify_q_diff(root, source, qualification):
    hexid(source, 40); hexid(qualification, 40)
    subprocess.run(['git', '-C', str(root), 'merge-base', '--is-ancestor', source, qualification], check=True, capture_output=True)
    # Check every commit, so an intermediate source edit cannot be hidden by a revert.
    changed = set()
    commits = git(root, 'rev-list', source + '..' + qualification).splitlines()
    for commit in commits:
        parents = git(root, 'rev-list', '--parents', '-n', '1', commit).split()[1:]
        require(len(parents) == 1, 'evidence-only history cannot contain merges')
        raw = subprocess.check_output(['git', '-C', str(root), 'diff', '--name-only', '-z', parents[0], commit])
        paths = [p.decode() for p in raw.split(b'\0') if p]
        require(all(evidence_path(path) for path in paths), 'Q is not evidence-only')
        changed.update(paths)
    return sorted(changed)


def create_manifest(source, bundle, artifacts, output):
    """Seal a clean committed build; all outputs must already exist."""
    source = Path(source)
    require(not git(source, 'status', '--porcelain', '--untracked-files=all'), 'candidate source must be clean')
    commit = git(source, 'rev-parse', 'HEAD')
    with tempfile.TemporaryDirectory(prefix='candidate-seal-') as tmp:
        root = extract_bundle(bundle, Path(tmp) / 'bundle')
        bundled = runtime.verify_bundle(root)
        require(bundled['memveil_revision'] == commit, 'bundle source differs from C')
        lock = read_json(source / 'toolchain.lock.json')
        pin = lock['dependencies']['libbpf-mojo']
        runtime.verify_sources(source, bundled, source / 'third_party' / ('libbpf-mojo-' + pin['version'] + '.tar.gz'))
        require(bundled['toolchain'] == lock['toolchain'], 'bundle toolchain differs')
        records = []
        for role in sorted(ROLES):
            path = Path(bundle if role == 'bundle' else artifacts[role])
            require(path.is_file() and not path.is_symlink(), 'artifact is not regular')
            records.append({'role': role, 'name': path.name, 'size': str(path.stat().st_size), 'sha256': runtime.digest(path)})
        doc = {'schema': SCHEMA, 'origin': 'local-build',
               'source': {'commit': commit, 'tree': git(source, 'rev-parse', 'HEAD^{tree}'),
                          'inventory_sha256': bundled['source_inventory_digest']},
               'toolchain': {'lock_sha256': runtime.digest(source / 'toolchain.lock.json'),
                             'pixi_lock_sha256': runtime.digest(source / 'pixi.lock')},
               'build_receipt_sha256': bundled['build_receipt_sha256'],
               'bundle_manifest_sha256': runtime.digest(root / 'MANIFEST.json'),
               'policy_sha256': runtime.digest(source / 'packaging/candidate-policy.json'),
               'canonical_runtime': bundled['canonical_runtime'], 'files': bundled['files'], 'artifacts': records}
        directories = {Path(bundle if role == 'bundle' else artifacts[role]).resolve().parent for role in ROLES}
        require(len(directories) == 1, 'retain all artifacts in one directory before sealing')
        import candidate_custody
        candidate_custody.verify_artifacts(source, doc, next(iter(directories)))
        return seal_manifest(doc, output)


def local_provenance(source, bundle, artifacts, output):
    source = Path(source)
    require(not git(source, 'status', '--porcelain', '--untracked-files=all'), 'provenance source must be clean')
    with tempfile.TemporaryDirectory(prefix='candidate-origin-') as tmp:
        root = extract_bundle(bundle, Path(tmp) / 'bundle')
        bundled = runtime.verify_bundle(root)
        commit = git(source, 'rev-parse', 'HEAD')
        require(bundled['memveil_revision'] == commit, 'bundle source differs')
        doc = {'schema': 'memveil-local-build/1', 'origin': 'local-build',
               'source': {'commit': commit, 'tree': git(source, 'rev-parse', 'HEAD^{tree}'),
                          'inventory_sha256': bundled['source_inventory_digest']},
               'toolchain': {'lock_sha256': runtime.digest(source / 'toolchain.lock.json'),
                             'pixi_lock_sha256': runtime.digest(source / 'pixi.lock')},
               'build_receipt_sha256': bundled['build_receipt_sha256'],
               'subjects': {Path(bundle if role == 'bundle' else artifacts[role]).name:
                   runtime.digest(bundle if role == 'bundle' else artifacts[role]) for role in ROLES - {'provenance'}}}
        write_once(output, canonical(doc))
        return digest_bytes(canonical(doc))


def verify_signature(subject, signature, public_key, trusted):
    require(runtime.digest(public_key) in trusted, 'untrusted signing key')
    data = read_regular(subject)
    read_regular(signature)
    key = read_regular(public_key).decode().strip()
    require(key.startswith('ssh-ed25519 ') and '\n' not in key, 'unsupported signing key')
    with tempfile.TemporaryDirectory(prefix='candidate-trust-') as tmp:
        allowed = Path(tmp) / 'allowed'
        allowed.write_text('qualifier ' + key + '\n')
        result = subprocess.run(['ssh-keygen', '-Y', 'verify', '-f', str(allowed),
            '-I', 'qualifier', '-n', 'memveil-candidate', '-s', str(signature)], input=data, capture_output=True)
    require(result.returncode == 0, 'signature verification failed')



def verify_measurement_sources(record, base):
    sources = record.get('sources')
    exact(sources, {'product', 'oracle'}, 'retained measurement sources')
    product_files = {binding['file'] for binding in sources['product'].values()}
    oracle_files = {binding['file'] for binding in sources['oracle'].values()}
    require(not product_files & oracle_files, 'product and oracle measurements require separate retained sources')
    for side in ('product', 'oracle'):
        exact(sources[side], record[side], side + ' source bindings')
        for name, binding in sources[side].items():
            exact(binding, {'file', 'sha256', 'path', 'encoding'}, 'measurement source binding')
            path = Path(base) / relative(binding['file'])
            data = read_regular(path)
            require(digest_bytes(data) == hexid(binding['sha256']), 'retained measurement file changed')
            value = read_json(path)
            require(canonical(value) == canonical(json.loads(data, object_pairs_hook=unique)), 'measurement file changed while reading')
            require(isinstance(binding['path'], list) and len(binding['path']) <= 64, 'invalid measurement path')
            for key in binding['path']:
                require((isinstance(value, dict) and isinstance(key, str) and key in value) or
                        (isinstance(value, list) and type(key) is int and 0 <= key < len(value)), 'measurement path absent')
                value = value[key]
            if binding['encoding'] == 'boolean':
                require(type(value) is bool, 'measurement boolean required')
                value = '1' if value else '0'
            else:
                require(binding['encoding'] == 'u64' and (type(value) is int or isinstance(value, str)), 'unsigned measurement required')
                value = str(value)
                runtime.parse_size(value)
            require(value == record[side][name], 'retained measurement differs: ' + side + '/' + name)


def rederive_measurements(record, requirement):
    require(set(record) in ({'schema', 'environment', 'product', 'oracle'},
                           {'schema', 'environment', 'product', 'oracle', 'sources'}), 'gate inputs have invalid fields')
    require(record['schema'] == 'memveil-gate-input/1', 'unsupported gate input schema')
    require(record['environment'] == requirement['environment'], 'gate environment mismatch')
    predicates = requirement['predicates']
    require(bool(predicates), 'empty gate predicates')
    exact(record['product'], predicates, 'product measurements')
    exact(record['oracle'], predicates, 'oracle measurements')
    for name, operation in predicates.items():
        actual = runtime.parse_size(record['product'][name])
        expected = runtime.parse_size(record['oracle'][name])
        if name in requirement.get('limits', {}):
            require(record['oracle'][name] == requirement['limits'][name], 'oracle threshold differs from fixed policy: ' + name)
        if operation == 'equal':
            require(actual == expected and expected > 0, 'oracle counts differ: ' + name)
        elif operation == 'zero':
            require(actual == expected == 0, 'loss or cleanup failure: ' + name)
        elif operation == 'at-least':
            require(actual >= expected > 0, 'minimum measurement failed: ' + name)
        elif operation == 'at-most':
            require(actual <= expected and expected > 0, 'maximum measurement failed: ' + name)
        else:
            raise ValueError('unknown oracle predicate')
    if requirement.get('adapter') == 'paced-replay/1':
        actual, oracle = record['product'], record['oracle']
        minimum = (runtime.parse_size(oracle['read_bytes']) + 65535) // 65536 + 1
        require(runtime.parse_size(oracle['read_calls']) == minimum and
                runtime.parse_size(actual['read_calls']) >= minimum, 'real read/EOF calls were not proven')
        require(runtime.parse_size(actual['rss_bytes']) > 0, 'RSS measurement is absent')
        require(runtime.parse_size(actual['max_request_bytes']) > 0, 'read request measurement is absent')
    return True


def validate_policy(policy):
    exact(policy, {'schema', 'claim', 'required_gates', 'trusted_keys', 'retention_days'}, 'policy')
    require(policy['schema'] == 'memveil-candidate-policy/1', 'unsupported candidate policy')
    require(policy['claim'] in ('ordinary-preview', 'snp-journal', 'security-workflow'), 'unsupported release claim')
    require(isinstance(policy['trusted_keys'], list), 'invalid trusted keys')
    for key in policy['trusted_keys']: hexid(key)
    require(30 <= runtime.parse_size(policy['retention_days']) <= 90, 'campaign retention must be 30 to 90 days')
    require(isinstance(policy['required_gates'], dict) and policy['required_gates'], 'required gates are empty')
    for ident, gate in policy['required_gates'].items():
        require(re.fullmatch(r'[a-z][a-z0-9-]*/[1-9][0-9]*', ident), 'gate IDs must be versioned')
        require({'environment', 'predicates'} <= set(gate) <= {'environment', 'predicates', 'limits', 'adapter'}, 'gate policy has invalid fields')
        require(gate.get('adapter') in (None, 'paced-replay/1'), 'unknown gate adapter')
        for name, value in gate.get('limits', {}).items():
            require(name in gate['predicates'], 'limit without predicate')
            runtime.parse_size(value)
        require(gate['environment'] in ('offline', 'ordinary-linux', 'snp', 'tdx', 'hyperv'), 'unknown gate environment')
        require(isinstance(gate['predicates'], dict) and gate['predicates'], 'empty required predicates')
        for name, op in gate['predicates'].items():
            require(re.fullmatch(r'[a-z][a-z0-9_-]*', name) and op in ('equal', 'zero', 'at-most', 'at-least'), 'invalid gate predicate')
    environments = {gate['environment'] for gate in policy['required_gates'].values()}
    if policy['claim'] != 'ordinary-preview': require('snp' in environments, 'SNP qualification required')
    if policy['claim'] == 'security-workflow': require({'tdx', 'hyperv'} <= environments, 'TDX and Hyper-V qualification required')
    return policy


def verify_qualification(manifest_path, qualification_path, policy_path, evidence, matrix_lock_path=None):
    manifest = load_manifest(manifest_path)
    candidate_id = runtime.digest(manifest_path)
    require(runtime.digest(policy_path) == manifest['policy_sha256'], 'policy differs from candidate')
    policy = validate_policy(read_json(policy_path))
    doc = read_json(qualification_path, sealed=True)
    exact(doc, {'schema', 'candidate_sha256', 'source_commit', 'claim', 'gates', 'evidence_archive'}, 'qualification')
    require(doc['schema'] == 'memveil-qualification/1' and doc['candidate_sha256'] == candidate_id and
            doc['source_commit'] == manifest['source']['commit'] and doc['claim'] == policy['claim'], 'qualification subject mismatch')
    exact(doc['gates'], policy['required_gates'], 'required qualification gates')
    base = Path(evidence)
    for ident, gate in doc['gates'].items():
        exact(gate, {'receipt', 'receipt_sha256', 'signature', 'public_key'}, 'gate receipt binding')
        for key in ('receipt', 'signature', 'public_key'): relative(gate[key])
        receipt = base / gate['receipt']
        require(runtime.digest(receipt) == hexid(gate['receipt_sha256']), 'retained receipt changed')
        verify_signature(receipt, base / gate['signature'], base / gate['public_key'], policy['trusted_keys'])
        record = read_json(receipt, sealed=True)
        exact(record, {'schema', 'gate', 'candidate_sha256', 'source_commit', 'inputs', 'inputs_sha256'}, 'signed gate receipt')
        require(record['schema'] == 'memveil-gate-receipt/1' and record['gate'] == ident and
                record['candidate_sha256'] == candidate_id and record['source_commit'] == manifest['source']['commit'], 'gate subject mismatch')
        relative(record['inputs'])
        inputs = base / record['inputs']
        require(runtime.digest(inputs) == hexid(record['inputs_sha256']), 'retained gate inputs changed')
        retained = read_json(inputs, sealed=True)
        if ident == 'kernel-matrix/2':
            exact(retained, {'schema', 'matrix_directory', 'lock_sha256'}, 'matrix input binding')
            require(retained['schema'] == 'memveil-matrix-input/1' and matrix_lock_path is not None, 'matrix requires pinned source lock')
            require(runtime.digest(matrix_lock_path) == hexid(retained['lock_sha256']), 'matrix lock differs')
            import sys
            sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tests/vm'))
            import kernel_matrix
            kernel_matrix.parse_lock(matrix_lock_path)
            with tempfile.TemporaryDirectory(prefix='candidate-matrix-') as tmp:
                kernel_matrix.export_tested_candidate(base / relative(retained['matrix_directory']),
                    read_json(matrix_lock_path), manifest, Path(tmp) / 'tested')
        else:
            verify_measurement_sources(retained, base)
            rederive_measurements(retained, policy['required_gates'][ident])
    return doc


def expected_payload(manifest):
    result = {}
    for name, digest in manifest['files'].items():
        result['bundle/' + name] = digest
        for kind in ('deb', 'rpm'):
            result[kind + '/' + runtime.installed_file_path(name)] = digest
    return result


def verify_signed_checksums(manifest, evidence, trusted):
    evidence = Path(evidence)
    verify_signature(evidence / 'SHA256SUMS.txt', evidence / 'SHA256SUMS.txt.sig', evidence / 'signer.pub', trusted)
    expected = ''.join(entry['sha256'] + '  ' + entry['name'] + '\n'
                       for entry in sorted(manifest['artifacts'], key=lambda entry: entry['name']))
    require(read_regular(evidence / 'SHA256SUMS.txt') == expected.encode(), 'signed checksums differ from candidate')
    return expected


def verify_tested_payload(manifest, tested_path):
    entries = {}
    for line in read_regular(tested_path).decode().splitlines():
        if not line.strip() or line.startswith('#'): continue
        parts = line.split()
        require(len(parts) == 2, 'invalid tested payload line')
        digest, name = parts
        hexid(digest)
        require(name not in entries, 'duplicate tested payload entry')
        entries[name] = digest
    require(entries == expected_payload(manifest), 'Q tested payload differs from candidate closure')
    return entries


def qualify_candidate(source, manifest_path, qualification_path, policy_path, evidence_archive, matrix_lock, output):
    import candidate_custody
    manifest = load_manifest(manifest_path)
    directory = Path(manifest_path).resolve().parent
    candidate_custody.verify_artifacts(source, manifest, directory)
    candidate_custody.verify_source(source, manifest)
    verify_q_diff(source, manifest['source']['commit'], git(source, 'rev-parse', 'HEAD'))
    changes = subprocess.check_output(['git', '-C', str(source), 'diff', '--name-only', '-z', 'HEAD'])
    changes += subprocess.check_output(['git', '-C', str(source), 'ls-files', '--others', '--exclude-standard', '-z'])
    require(all(evidence_path(path.decode()) for path in changes.split(b'\0') if path), 'qualification source has non-evidence changes')
    pinned_matrix = subprocess.check_output(['git', '-C', str(source), 'show', manifest['source']['commit'] + ':tests/vm/kernels.lock.json'])
    require(runtime.digest(matrix_lock) == digest_bytes(pinned_matrix), 'matrix lock differs from C')
    doc = read_json(qualification_path, sealed=True)
    verify_file(evidence_archive, doc['evidence_archive'])
    with tempfile.TemporaryDirectory(prefix='candidate-qualify-') as tmp:
        evidence = extract_bundle(evidence_archive, Path(tmp) / 'evidence')
        verify_qualification(manifest_path, qualification_path, policy_path, evidence, matrix_lock)
        verify_signed_checksums(manifest, evidence, read_json(policy_path)['trusted_keys'])
    expected = expected_payload(manifest)
    write_once(output, ''.join(value + '  ' + name + '\n' for name, value in sorted(expected.items())).encode())
    return expected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    seal = commands.add_parser('seal', help='seal existing local outputs, without building')
    seal.add_argument('--source-tree', default='.')
    for role in sorted(ROLES): seal.add_argument('--' + role, required=True)
    seal.add_argument('--out', required=True)
    origin = commands.add_parser('provenance', help='record truthful local origin of existing outputs')
    origin.add_argument('--source-tree', default='.')
    for role in sorted(ROLES - {'provenance'}): origin.add_argument('--' + role, required=True)
    origin.add_argument('--out', required=True)
    qualify = commands.add_parser('qualify', help='rederive all required signed gates and export tested payload')
    qualify.add_argument('--source-tree', default='.')
    for name in ('manifest', 'qualification', 'policy', 'evidence-archive', 'matrix-lock', 'out'):
        qualify.add_argument('--' + name, required=True)
    verify = commands.add_parser('verify-bundle', help='verify and exclusively extract exact runtime')
    verify.add_argument('--manifest', required=True)
    verify.add_argument('--digest')
    verify.add_argument('--bundle', required=True)
    verify.add_argument('--destination', required=True)
    args = parser.parse_args()
    try:
        if args.command == 'seal':
            print(create_manifest(args.source_tree, args.bundle, vars(args), args.out))
        elif args.command == 'provenance':
            print(local_provenance(args.source_tree, args.bundle, vars(args), args.out))
        elif args.command == 'qualify':
            qualify_candidate(args.source_tree, args.manifest, args.qualification, args.policy,
                              args.evidence_archive, args.matrix_lock, args.out)
            print('all required signed qualification inputs re-derived')
        else:
            print(verify_bundle(load_manifest(args.manifest, args.digest), args.bundle, args.destination))
    except (OSError, ValueError, KeyError, StopIteration, subprocess.CalledProcessError, tarfile.TarError) as error:
        parser.exit(1, 'candidate: ' + str(error) + '\n')


if __name__ == '__main__':
    main()
