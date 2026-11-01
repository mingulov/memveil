# SPDX-License-Identifier: GPL-3.0-or-later
"""Re-run matrix predicates from retained synthetic inputs, never status strings."""
import copy
import json
from pathlib import Path
import sys
import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tests/vm'))
import kernel_matrix as km
from test_kernel_matrix import _ev_pass


def test_matrix_retained_predicates_ignore_declared_pass():
    assert hasattr(km, 'rederive_inputs'), 'matrix oracle inputs cannot be re-derived'
    ev = _ev_pass()
    assert km.rederive_inputs(ev)['ok']
    for damage in ('actual', 'oracle', 'expected', 'skipped'):
        bad = copy.deepcopy(ev)
        if damage == 'actual': bad['persisted']['bounce_attempt'] = 1
        if damage == 'oracle': bad['oracle_text'] = bad['oracle_text'].replace('13000', '999999')
        if damage == 'expected': bad['entry']['expected']['attempt-trace']['verdict'] = 'refused'
        if damage == 'skipped': bad['vng_exit'] = '77'
        assert not km.rederive_inputs(bad)['ok'], damage


def test_matrix_export_requires_exact_required_rows(tmp_path):
    assert hasattr(km, 'export_tested_candidate'), 'matrix tested export is missing'
    with pytest.raises(ValueError):
        km.export_tested_candidate(tmp_path, {'kernels': []}, {}, tmp_path / 'tested')
    assert not (tmp_path / 'tested').exists()


def matrix_tool():
    from importlib.machinery import SourceFileLoader
    from importlib.util import spec_from_loader, module_from_spec
    loader = SourceFileLoader('candidate_matrix_tool', str(ROOT / 'tools/kernel-matrix'))
    spec = spec_from_loader(loader.name, loader)
    module = module_from_spec(spec); loader.exec_module(module)
    return module


sys.path.insert(0, str(ROOT / 'tests'))
from support.test_candidate_input import sealed


def test_matrix_cli_override_refuses_before_guest(monkeypatch, sealed):
    from types import SimpleNamespace
    from support import candidate_input
    for key in candidate_input.OVERRIDES: monkeypatch.delenv(key, raising=False)
    selected = candidate_input.load(env=sealed)
    monkeypatch.setattr(candidate_input, '_cached', selected)
    for key, value in sealed.items(): monkeypatch.setenv(key, value)
    with pytest.raises(ValueError, match='override'):
        matrix_tool().select_candidate_inputs(SimpleNamespace(deb='/foreign.deb', bundle=None, scenarios=False))
    selected.close()


def test_matrix_uses_verified_bundle_and_exact_deb_adapter(monkeypatch, sealed):
    from types import SimpleNamespace
    from support import candidate_input
    for key in candidate_input.OVERRIDES: monkeypatch.delenv(key, raising=False)
    selected = candidate_input.load(env=sealed)
    monkeypatch.setattr(candidate_input, '_cached', selected)
    for key, value in sealed.items(): monkeypatch.setenv(key, value)
    args = SimpleNamespace(deb=None, bundle=None, scenarios=False)
    assert matrix_tool().select_candidate_inputs(args) is selected
    assert args.bundle == str(selected.root)
    args = SimpleNamespace(deb=str(selected.artifact('deb')), bundle=None, scenarios=False)
    assert matrix_tool().select_candidate_inputs(args) is selected
    assert args.deb == str(selected.artifact('deb'))
    selected.close()


def exported_fixture(tmp_path):
    import candidate as c
    from test_candidate import manifest
    from test_kernel_matrix import _row_ctx, _row_job
    ev = _ev_pass(); ev['duration'] = 60
    hooks = json.loads(ev['hooks_text']); hooks['btf'] = True; ev['hooks_text'] = json.dumps(hooks)
    doc = manifest()
    doc['canonical_runtime']['entries'][0]['sha256'] = 'a' * 64
    doc['files']['bin/memveil'] = 'a' * 64
    doc['canonical_runtime']['entries'] = [entry for entry in doc['canonical_runtime']['entries'] if not entry['path'].startswith('bpf/')]
    del doc['files']['bpf/probe.bpf.o']
    for name, value in [('attempt', 'b'), ('lifecycle', 'c'), ('copy', 'd')]:
        path = 'bpf/swiotlb_' + name + '.bpf.o'
        doc['files'][path] = value * 64
        doc['canonical_runtime']['entries'].append({'path': path, 'type': 'file', 'size': '1', 'sha256': value * 64})
    doc['canonical_runtime']['entries'].sort(key=lambda entry: entry['path'])
    ev['candidate_sha256'] = c.digest_bytes(c.canonical(doc))
    ev['canonical_runtime'] = copy.deepcopy(doc['canonical_runtime'])
    rec = km.evaluate_row(ev)
    assert rec['ok'], rec
    rec.update(run_id='20261101T000000Z', elapsed=1.0, timeout=False, release=ev['entry']['release'])
    row = tmp_path / ev['entry']['id']; row.mkdir()
    job = _row_job(); job.update(id=ev['entry']['id'], release=ev['entry']['release'], run_id=rec['run_id'])
    files = {'job.json': json.dumps(job), 'oracle-inputs.json': json.dumps(ev), 'vng.exit': '0',
             'artifacts.json': ev['artifacts_text'], 'uname.txt': ev['uname_text'], 'mods.txt': ev['mods_text'],
             'hooks.json': ev['hooks_text'], 'btf-sha.txt': '2'*64, 'oracle.txt': ev['oracle_text'],
             'oracle.stderr': ev['oracle_stderr'], 'oracle.mode': 'full'}
    for name, value in files.items(): (row / name).write_text(value)
    ctx = _row_ctx(kernel_selector='--kernel ' + ev['entry']['id'], source_sha256=c.artifact(doc, 'deb')['sha256'])
    ctx['source']['memveil'] = {'commit': doc['source']['commit'], 'dirty': False}
    ctx['toolchain']['lock_sha256'] = doc['toolchain']['lock_sha256']
    receipt = km.write_row_receipt(row, rec, ev['entry'], ctx)
    (tmp_path / (ev['entry']['id'] + '.json')).write_text(json.dumps(rec))
    (tmp_path / 'summary.json').write_text(json.dumps([rec]))
    return doc, {'kernels': [copy.deepcopy(ev['entry'])]}, row, ev, rec, receipt


def test_matrix_export_reexecutes_every_required_row(tmp_path):
    import candidate as c
    doc, lock, row, ev, rec, receipt = exported_fixture(tmp_path)
    output = tmp_path / 'tested.txt'
    assert km.export_tested_candidate(tmp_path, lock, doc, output) == c.expected_payload(doc)
    assert output.read_text() == ''.join(value + '  ' + name + '\n' for name, value in sorted(c.expected_payload(doc).items()))
    with pytest.raises(FileExistsError): km.export_tested_candidate(tmp_path, lock, doc, output)


@pytest.mark.parametrize('damage', ['actual', 'oracle', 'expected', 'missing-row', 'source', 'profile', 'toolchain', 'package', 'bpf'])
def test_matrix_export_rejects_tamper_even_when_old_checks_say_pass(tmp_path, damage):
    doc, lock, row, ev, rec, receipt = exported_fixture(tmp_path)
    if damage == 'actual': ev['persisted']['bounce_attempt'] = 1
    if damage == 'oracle': ev['oracle_text'] = ev['oracle_text'].replace('13000', '999999')
    if damage == 'expected': ev['entry']['expected']['attempt-trace']['verdict'] = 'refused'
    if damage == 'missing-row': lock['kernels'].append(dict(lock['kernels'][0], id='required-extra'))
    if damage == 'source': receipt['source']['memveil']['commit'] = '9' * 40
    if damage == 'toolchain': receipt['toolchain']['lock_sha256'] = '9' * 64
    if damage == 'profile': ev['canonical_runtime']['entries'][-1]['sha256'] = '9' * 64
    if damage == 'package': receipt['command']['source_sha256'] = '9' * 64
    if damage == 'bpf':
        measured = json.loads((row / 'artifacts.json').read_text())
        measured['bpf']['attempt'] = '9' * 64
        (row / 'artifacts.json').write_text(json.dumps(measured))
        ev['artifacts_text'] = json.dumps(measured)
        receipt['artifacts']['bpf']['attempt'] = '9' * 64
    # Update the unsigned transcription hashes; the old PASS booleans remain.
    (row / 'oracle-inputs.json').write_text(json.dumps(ev))
    receipt['files'] = km.row_receipt_files(row)
    (row / 'receipt.json').write_text(json.dumps(receipt))
    output = tmp_path / 'refused.txt'
    with pytest.raises(ValueError): km.export_tested_candidate(tmp_path, lock, doc, output)
    assert not output.exists()
