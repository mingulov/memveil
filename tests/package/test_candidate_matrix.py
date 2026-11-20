# SPDX-License-Identifier: GPL-3.0-or-later
"""Tested export re-derives every required row from retained evidence.

The export replays the matrix predicates from the cached oracle
inputs only after proving the cache matches the retained raw files,
then binds the row to the exact candidate closure before writing.
"""
import copy
import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tests/vm'))
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'tests/package'))
import kernel_matrix as km
import candidate as c
from test_kernel_matrix import _admitted_entry
from test_candidate import (_ephemeral_key, _write_policy,
                            _write_qualification, _signed_gate,
                            _matrix_lock, _write_real_matrix_row,
                            sha)


def _matrix_manifest(commit='c' * 40, policy_sha='9' * 64):
    files = {'bin/memveil': 'a' * 64,
             'lib/memveil/libx.so.1': 'e' * 64,
             'bpf/swiotlb_attempt.bpf.o': 'b' * 64,
             'bpf/swiotlb_lifecycle.bpf.o': 'c' * 64,
             'bpf/swiotlb_copy.bpf.o': 'd' * 64,
             'profiles/test.json': 'f' * 64}
    leaves = {'bundle': 'bundle.tar.gz', 'deb': 'memveil.deb',
              'rpm': 'memveil.rpm', 'source': 'source.tar.gz',
              'sbom': 'sbom.spdx.json',
              'provenance': 'provenance.json'}
    shas = {'bundle': '1' * 64, 'deb': '2' * 64,
            'rpm': '3' * 64, 'source': '4' * 64,
            'sbom': '5' * 64, 'provenance': '6' * 64}
    arts = [{'role': role, 'name': leaves[role], 'size': '10',
             'sha256': shas[role]} for role in sorted(leaves)]
    return {'schema': 'memveil-candidate/2',
            'origin': 'local-build',
            'source': {'commit': commit, 'tree': 'd' * 40,
                       'inventory_sha256': 'e' * 64},
            'toolchain': {'cargo_lock_sha256': 'f0' * 32,
                          'ebpf_lock_sha256': '0f' * 32,
                          'tools': {'cargo': '1.100.0',
                                    'rustc': '1.100.0',
                                    'bpf_linker': '0.10.4'}},
            'build_receipt_sha256': '7' * 64,
            'bundle_manifest_sha256': '8' * 64,
            'policy_sha256': policy_sha, 'files': files,
            'artifacts': arts}


def exported_fixture(tmp_path, commit='c' * 40,
                     policy_sha='9' * 64):
    assert hasattr(km, 'export_tested_candidate'), \
        'matrix tested export is missing'
    tmp_path = Path(tmp_path)
    tmp_path.mkdir(parents=True, exist_ok=True)
    doc = _matrix_manifest(commit=commit, policy_sha=policy_sha)
    ev, rec, receipt, row = _write_real_matrix_row(
        c, tmp_path, doc)
    lock = _matrix_lock(copy.deepcopy(ev['entry']))
    return doc, lock, row, ev, rec, receipt


def test_export_requires_exact_required_rows(tmp_path):
    assert hasattr(km, 'export_tested_candidate'), \
        'matrix tested export is missing'
    with pytest.raises(ValueError):
        km.export_tested_candidate(tmp_path, {'kernels': []},
                                   {}, tmp_path / 'tested')
    assert not (tmp_path / 'tested').exists()


def test_export_accepts_consistent_row(tmp_path):
    doc, lock, row, ev, rec, receipt = exported_fixture(tmp_path)
    output = tmp_path / 'tested.txt'
    assert km.export_tested_candidate(
        tmp_path, lock, doc, output) == c.expected_payload(doc)
    assert output.read_text() == ''.join(
        value + '  ' + name + '\n'
        for name, value in sorted(c.expected_payload(doc).items()))
    with pytest.raises(FileExistsError):
        km.export_tested_candidate(tmp_path, lock, doc, output)


@pytest.mark.parametrize('damage,blame', [
    ('actual', None), ('oracle', None), ('expected', None),
    ('missing-row', None), ('source', None), ('profile', None),
    ('toolchain', None), ('package', None), ('bpf', None),
    ('engine', 'matrix executable differs'),
    ('smoke', 'smoke-only'),
    ('entry', 'pinned lock')])
def test_export_rejects_tampered_cache_x12(tmp_path, damage,
                                           blame):
    doc, lock, row, ev, rec, receipt = exported_fixture(tmp_path)
    if damage == 'actual':
        ev['persisted']['bounce_attempt'] = 1
    if damage == 'oracle':
        ev['oracle_text'] = ev['oracle_text'].replace(
            '13000', '999999')
    if damage == 'expected':
        ev['entry']['expected']['attempt-trace']['verdict'] = \
            'refused'
    if damage == 'missing-row':
        lock['kernels'].append(
            dict(lock['kernels'][0], id='required-extra'))
    if damage == 'source':
        receipt['source']['memveil']['commit'] = '9' * 40
    if damage == 'toolchain':
        receipt['toolchain']['lock_sha256'] = '9' * 64
    if damage == 'profile':
        ev['candidate_files']['profiles/test.json'] = '9' * 64
    if damage == 'package':
        receipt['command']['source_sha256'] = '9' * 64
    if damage == 'bpf':
        measured = json.loads((row / 'artifacts.json').read_text())
        measured['bpf']['attempt'] = '9' * 64
        (row / 'artifacts.json').write_text(json.dumps(measured))
        ev['artifacts_text'] = json.dumps(measured)
        receipt['artifacts']['bpf']['attempt'] = '9' * 64
    if damage == 'engine':
        # Same attack shape as the qualify-side foreign-bytes
        # test: the row tested a different engine, kept
        # consistent across retained, cached, and receipt
        # bytes, so only the shared binding refuses, with the
        # same blame the qualify path reports.
        measured = json.loads((row / 'artifacts.json').read_text())
        measured['binary']['sha256'] = '9' * 64
        (row / 'artifacts.json').write_text(json.dumps(measured))
        ev['artifacts_text'] = json.dumps(measured)
        receipt['artifacts']['binary_sha256'] = '9' * 64
    if damage == 'smoke':
        job = json.loads((row / 'job.json').read_text())
        job['duration'] = 61
        (row / 'job.json').write_text(json.dumps(job))
        receipt['command']['duration_s'] = 61
        receipt['workload']['duration_s'] = 61
        receipt['smoke'] = True
    if damage == 'entry':
        assert ev['entry']['upstream'] != '9.9.99'
        ev['entry']['upstream'] = '9.9.99'
    # Update the unsigned transcription hashes; the old PASS
    # booleans remain.
    (row / 'oracle-inputs.json').write_text(json.dumps(ev))
    receipt['files'] = km.row_receipt_files(row)
    (row / 'receipt.json').write_text(json.dumps(receipt))
    output = tmp_path / 'refused.txt'
    with pytest.raises(ValueError, match=blame):
        km.export_tested_candidate(tmp_path, lock, doc, output)
    assert not output.exists()


def test_verify_refuses_v1_row_at_rust_binding(tmp_path):
    doc, lock, row, ev, rec, receipt = exported_fixture(tmp_path)
    # A historical /1 receipt: structurally valid (it
    # re-derives PASS) but its Mojo-era sections predate the
    # Rust row bindings, so acceptance refuses at the version
    # gate instead of comparing across meanings.
    receipt["schema"] = "memveil-matrix-row/1"
    receipt["source"] = {
        "memveil": {"commit": doc["source"]["commit"],
                    "dirty": False},
        "libbpf_mojo": {"version": "0.3.0",
                        "tarball_sha256": "f" * 64,
                        "status": "pinned"}}
    receipt["toolchain"] = {
        "lock_version": "1",
        "recorded_on": "2026-10-24",
        "lock_sha256": "a" * 64,
        "toolchain": {"mojo": {"version": "1.2.0"},
                      "pixi": {"version": "0.1.0"}}}
    (row / "receipt.json").write_text(json.dumps(receipt))
    assert km.rederive_row(row)[0]
    with pytest.raises(ValueError, match="predates Rust bindings"):
        km.verify_tested_rows(tmp_path, lock, doc)
    output = tmp_path / "refused.txt"
    with pytest.raises(ValueError, match="predates Rust bindings"):
        km.export_tested_candidate(tmp_path, lock, doc, output)
    assert not output.exists()


def test_export_rejects_receipt_missing_one_bpf_object(tmp_path):
    doc, lock, row, ev, rec, receipt = exported_fixture(tmp_path)
    del receipt['artifacts']['bpf']['copy']
    receipt['files'] = km.row_receipt_files(row)
    (row / 'receipt.json').write_text(json.dumps(receipt))
    output = tmp_path / 'refused.txt'
    with pytest.raises(ValueError):
        km.export_tested_candidate(tmp_path, lock, doc, output)
    assert not output.exists()


@pytest.mark.parametrize('target', ['oracle.txt', 'oracle.stderr',
                                    'artifacts.json', 'uname.txt'])
def test_export_rejects_raw_mutation_with_fresh_hashes(
        tmp_path, target):
    doc, lock, row, ev, rec, receipt = exported_fixture(tmp_path)
    if target == 'oracle.txt':
        (row / 'oracle.txt').write_text(
            (row / 'oracle.txt').read_text().replace(
                '13000', '999999'))
        receipt['oracle']['text_sha256'] = sha(
            (row / 'oracle.txt').read_bytes())
    elif target == 'oracle.stderr':
        (row / 'oracle.stderr').write_text(
            (row / 'oracle.stderr').read_text() + 'note: kept\n')
        receipt['oracle']['lost_events'] = \
            km.parse_oracle_losses(
                (row / 'oracle.stderr').read_text())[1]
    elif target == 'artifacts.json':
        measured = json.loads((row / 'artifacts.json').read_text())
        measured['dpkg_version'] = '0.1.0-2'
        (row / 'artifacts.json').write_text(json.dumps(measured))
        receipt['artifacts']['dpkg_version'] = '0.1.0-2'
    else:
        (row / 'uname.txt').write_text(
            (row / 'uname.txt').read_text().replace(
                '070014', '999999'))
        receipt['kernel']['uname'] = \
            (row / 'uname.txt').read_text().strip()
    # Refresh the unsigned row transcription and inventory so
    # both sides verify alone; only the cache/raw comparison
    # can refuse.
    receipt['files'] = km.row_receipt_files(row)
    (row / 'receipt.json').write_text(json.dumps(receipt))
    output = tmp_path / 'refused.txt'
    with pytest.raises(ValueError,
                      match='cached .* differs from retained'):
        km.export_tested_candidate(tmp_path, lock, doc, output)
    assert not output.exists()


def test_verify_row_cache_vs_raw(tmp_path):
    assert hasattr(km, 'verify_row_cache_vs_raw'), \
        'matrix cache/raw check is missing'
    doc, lock, row, ev, rec, receipt = exported_fixture(tmp_path)
    assert km.verify_row_cache_vs_raw(row, ev) is None
    bad = copy.deepcopy(ev)
    bad['oracle_text'] = bad['oracle_text'].replace(
        '13000', '999999')
    with pytest.raises(ValueError, match='differs from retained'):
        km.verify_row_cache_vs_raw(row, bad)
    with pytest.raises(ValueError):
        km.verify_row_cache_vs_raw(row, {'oracle_text': 'x'})
    with pytest.raises(ValueError):
        km.verify_row_cache_vs_raw(row, None)


@pytest.mark.parametrize('field,value', [
    ('vng_exit', '1'),
    ('fail_txt', 'guest failed\n'),
    ('doctor_exit', '1'),
    ('doctor_passive_exit', '1'),
    ('record_exit', '0'),
    ('report_exit', '0'),
    ('report_json_exit', '0'),
    ('udev_exit', '1\n'),
    ('udev_out', 'tampered\n'),
    ('busy_record_exit', '1'),
    ('busy_end_reason', 'tampered\n'),
    ('busy_report_exit', '1'),
    ('busy_report_json_exit', '1'),
    ('oracle_mode', 'countonly'),
])
def test_cache_scalar_mismatch_refuses(tmp_path, field, value):
    doc, lock, row, ev, rec, receipt = exported_fixture(tmp_path)
    bad = copy.deepcopy(ev)
    bad[field] = value
    with pytest.raises(ValueError, match='differs from retained'):
        km.verify_row_cache_vs_raw(row, bad)


def test_cache_refusal_mismatch_refuses(tmp_path):
    doc, lock, row, ev, rec, receipt = exported_fixture(tmp_path)
    bad = copy.deepcopy(ev)
    bad['refusals'] = {'cap-attempt-trace': {
        'exit': '0', 'out': '', 'exists': '1'}}
    with pytest.raises(ValueError, match='differs from retained'):
        km.verify_row_cache_vs_raw(row, bad)


def test_missing_retained_exit_refuses(tmp_path):
    doc, lock, row, ev, rec, receipt = exported_fixture(tmp_path)
    (row / 'record.exit').unlink()
    with pytest.raises(ValueError, match='differs from retained'):
        km.verify_row_cache_vs_raw(row, ev)


@pytest.mark.parametrize('field', ['miss_snaps',
                                    'busy_miss_snaps'])
def test_cache_snaps_mismatch_refuses(tmp_path, field):
    doc, lock, row, ev, rec, receipt = exported_fixture(tmp_path)
    bad = copy.deepcopy(ev)
    bad[field][0][0] += 1
    with pytest.raises(ValueError, match='differs from retained'):
        km.verify_row_cache_vs_raw(row, bad)


@pytest.mark.parametrize('key,sub', [
    ('persisted', 'bounce_attempt'),
    ('persisted_bytes', 'requested'),
    ('persisted_copy_dirs', 'original_to_bounce'),
    ('counters', 'swiotlb.bounce_attempts'),
])
def test_cache_rederivation_mismatch_refuses(tmp_path, key,
                                             sub):
    doc, lock, row, ev, rec, receipt = exported_fixture(tmp_path)
    bad = copy.deepcopy(ev)
    bad[key][sub] = 1
    with pytest.raises(ValueError, match='differs from retained'):
        km.verify_row_cache_vs_raw(row, bad)


def test_cache_unpaired_mismatch_refuses(tmp_path):
    doc, lock, row, ev, rec, receipt = exported_fixture(tmp_path)
    bad = copy.deepcopy(ev)
    bad['unpaired_count'] = 1
    with pytest.raises(ValueError, match='differs from retained'):
        km.verify_row_cache_vs_raw(row, bad)


@pytest.mark.parametrize('field,value', [
    ('busy_persisted', {'bounce_attempt': 1}),
    ('busy_events_bytes', 1),
    ('busy_counters', {'swiotlb.bounce_attempts': 1}),
])
def test_cache_busy_mismatch_refuses(tmp_path, field, value):
    doc, lock, row, ev, rec, receipt = exported_fixture(tmp_path)
    bad = copy.deepcopy(ev)
    bad[field] = value
    with pytest.raises(ValueError, match='differs from retained'):
        km.verify_row_cache_vs_raw(row, bad)


@pytest.mark.parametrize('field', ['validate_rc',
                                    'busy_validate_rc'])
def test_cache_validate_rc_mismatch_refuses(tmp_path, field):
    doc, lock, row, ev, rec, receipt = exported_fixture(tmp_path)
    bad = copy.deepcopy(ev)
    bad[field] = 1
    with pytest.raises(ValueError, match='differs from retained'):
        km.verify_row_cache_vs_raw(row, bad)


def test_cache_validate_out_mismatch_refuses(tmp_path):
    doc, lock, row, ev, rec, receipt = exported_fixture(tmp_path)
    bad = copy.deepcopy(ev)
    bad['validate_out'] += 'tampered\n'
    with pytest.raises(ValueError, match='differs from retained'):
        km.verify_row_cache_vs_raw(row, bad)


@pytest.mark.parametrize('rel', ['validate.json',
                                  'busy/validate.json'])
def test_missing_validate_record_refuses(tmp_path, rel):
    doc, lock, row, ev, rec, receipt = exported_fixture(tmp_path)
    (row / rel).unlink()
    with pytest.raises(ValueError, match='cannot furnish'):
        km.verify_row_cache_vs_raw(row, ev)


def test_cache_redaction_mismatch_refuses(tmp_path):
    doc, lock, row, ev, rec, receipt = exported_fixture(tmp_path)
    bad = copy.deepcopy(ev)
    bad['export_redact_error'] = 'oracle.txt: redacted text'
    with pytest.raises(ValueError, match='differs from retained'):
        km.verify_row_cache_vs_raw(row, bad)


def matrix_tool():
    from importlib.machinery import SourceFileLoader
    from importlib.util import spec_from_loader, module_from_spec
    loader = SourceFileLoader('candidate_matrix_tool',
                              str(ROOT / 'tools/kernel-matrix'))
    spec = spec_from_loader(loader.name, loader)
    module = module_from_spec(spec)
    loader.exec_module(module)
    return module


sys.path.insert(0, str(ROOT / 'tests'))
from support.test_candidate_input import sealed


def test_matrix_cli_override_refuses_before_guest(
        monkeypatch, sealed):
    from types import SimpleNamespace
    from support import candidate_input
    for key in candidate_input.OVERRIDES:
        monkeypatch.delenv(key, raising=False)
    selected = candidate_input.load(env=sealed)
    monkeypatch.setattr(candidate_input, '_cached', selected)
    for key, value in sealed.items():
        monkeypatch.setenv(key, value)
    with pytest.raises(ValueError, match='override'):
        matrix_tool().select_candidate_inputs(SimpleNamespace(
            deb='/foreign.deb', bundle=None, scenarios=False))
    selected.close()


def test_matrix_uses_verified_bundle_and_exact_deb_adapter(
        monkeypatch, sealed):
    from types import SimpleNamespace
    from support import candidate_input
    for key in candidate_input.OVERRIDES:
        monkeypatch.delenv(key, raising=False)
    selected = candidate_input.load(env=sealed)
    monkeypatch.setattr(candidate_input, '_cached', selected)
    for key, value in sealed.items():
        monkeypatch.setenv(key, value)
    args = SimpleNamespace(deb=None, bundle=None, scenarios=False)
    assert matrix_tool().select_candidate_inputs(args) is selected
    assert args.bundle == str(selected.root)
    args = SimpleNamespace(deb=str(selected.artifact('deb')),
                           bundle=None, scenarios=False)
    assert matrix_tool().select_candidate_inputs(args) is selected
    assert args.deb == str(selected.artifact('deb'))
    selected.close()


def _init_lock_repo(path, lock_bytes):
    tree = Path(path) / 'tests/vm'
    tree.mkdir(parents=True)
    (tree / 'kernels.lock.json').write_bytes(lock_bytes)
    for args in (['init', '-q'], ['add', '.']):
        subprocess.run(['git', '-C', str(path), *args],
                       check=True, capture_output=True)
    subprocess.run(['git', '-C', str(path), '-c', 'user.name=t',
                    '-c', 'user.email=t@t', 'commit', '-qm',
                    'lock'], check=True, capture_output=True)
    proc = subprocess.run(['git', '-C', str(path), 'rev-parse',
                           'HEAD'], check=True,
                          capture_output=True, text=True)
    return proc.stdout.strip()


def _qualified_evidence(tmp_path):
    """Honest end-to-end export inputs over one synthetic row."""
    tmp_path = Path(tmp_path)
    tmp_path.mkdir(parents=True, exist_ok=True)
    key, pub = _ephemeral_key(tmp_path / 'key')
    gates = {'kernel-matrix/2':
             {'environment': 'ordinary-linux',
              'predicates': {'required_rows': 'equal',
                             'failed_rows': 'zero',
                             'skipped_rows': 'zero'}}}
    policy_path = tmp_path / 'policy.json'
    _write_policy(c, policy_path, gates, [sha(pub.read_bytes())])
    lock_bytes = c.canonical(_matrix_lock(_admitted_entry()))
    repo = tmp_path / 'source'
    commit = _init_lock_repo(repo, lock_bytes)
    lock_path = tmp_path / 'kernels.lock.json'
    lock_path.write_bytes(lock_bytes)
    evidence = tmp_path / 'evidence'
    out = evidence / 'matrix'
    doc, lock, row, ev, rec, receipt = exported_fixture(
        out, commit=commit,
        policy_sha=sha(policy_path.read_bytes()))
    manifest_path = tmp_path / 'candidate.json'
    manifest_path.write_bytes(c.canonical(doc))
    ctx = {'candidate_id': sha(manifest_path.read_bytes()),
           'manifest': doc, 'key': key, 'pub': pub}
    inventory = c.build_evidence_inventory(evidence, 'matrix')
    inputs = {'schema': 'memveil-matrix-input/2',
              'matrix_directory': 'matrix',
              'evidence_inventory_sha256':
              c.digest_canonical(inventory)}
    binding = _signed_gate(c, ctx, evidence, 'kernel-matrix/2',
                           'inputs.json', 'receipt.json', inputs)
    qualification_path = tmp_path / 'qualification.json'
    _write_qualification(c, ctx, qualification_path,
                         {'kernel-matrix/2': binding})
    return {'manifest': doc, 'manifest_path': manifest_path,
            'lock': lock, 'lock_path': lock_path, 'repo': repo,
            'commit': commit, 'evidence': evidence, 'out': out,
            'qualification': qualification_path,
            'policy': policy_path, 'row': row}


def _export_cli(ctx, dest, monkeypatch, lock_path=None):
    monkeypatch.setenv('MV_CANDIDATE_MANIFEST',
                       str(ctx['manifest_path']))
    return matrix_tool().main(
        ['--out', str(ctx['out']), '--verify-out',
         '--export-tested', str(dest),
         '--lock', str(lock_path or ctx['lock_path']),
         '--evidence-dir', str(ctx['evidence']),
         '--qualification', str(ctx['qualification']),
         '--policy', str(ctx['policy']),
         '--source-tree', str(ctx['repo'])])


def test_export_cli_accepts_qualified_evidence(
        tmp_path, monkeypatch):
    ctx = _qualified_evidence(tmp_path)
    dest = tmp_path / 'tested.txt'
    assert _export_cli(ctx, dest, monkeypatch) == 0
    assert dest.read_text() == ''.join(
        value + '  ' + name + '\n' for name, value in sorted(
            c.expected_payload(ctx['manifest']).items()))


def test_export_cli_refuses_unqualified_evidence(
        tmp_path, monkeypatch, capsys):
    ctx = _qualified_evidence(tmp_path)
    (ctx['row'] / 'oracle.txt').write_text(
        (ctx['row'] / 'oracle.txt').read_text() + 'tampered\n')
    refused = tmp_path / 'refused-inventory.txt'
    assert _export_cli(ctx, refused, monkeypatch) != 0
    assert not refused.exists()
    assert 'refused' in capsys.readouterr().err
    ctx = _qualified_evidence(tmp_path / 'second')
    (ctx['evidence'] / 'receipt.json.sig').write_bytes(b'bad\n')
    refused = tmp_path / 'refused-signature.txt'
    assert _export_cli(ctx, refused, monkeypatch) != 0
    assert not refused.exists()
    assert 'refused' in capsys.readouterr().err


def test_export_cli_refuses_drifted_lock(
        tmp_path, monkeypatch, capsys):
    ctx = _qualified_evidence(tmp_path)
    tool = matrix_tool()
    tool.verify_lock_matches_checkout(
        ctx['lock_path'], ctx['commit'], ctx['repo'])
    drifted = json.loads(ctx['lock_path'].read_bytes())
    drifted['archive_queried'] = '2026-11-20'
    drifted_path = tmp_path / 'drifted.lock.json'
    drifted_path.write_bytes(c.canonical(drifted))
    with pytest.raises(ValueError, match='differs from C'):
        tool.verify_lock_matches_checkout(
            drifted_path, ctx['commit'], ctx['repo'])
    refused = tmp_path / 'refused-lock.txt'
    assert _export_cli(ctx, refused, monkeypatch,
                       lock_path=drifted_path) != 0
    assert not refused.exists()
    assert 'differs from C' in capsys.readouterr().err
