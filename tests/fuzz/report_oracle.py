# SPDX-License-Identifier: GPL-3.0-or-later
"""Independent schema, literal-prefix and arithmetic oracle for accepted replay."""
import copy
import hashlib
import json
from pathlib import Path
import re
import runpy
import tempfile

ROOT = Path(__file__).resolve().parents[2]
V = runpy.run_path(str(ROOT / 'tools/validate-schemas'))
SCHEMA = json.loads((ROOT / 'schemas/report-v0.1.4.schema.json').read_text())


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def schema_check(value, rule, root=SCHEMA, where='report'):
    """Evaluate the closed vocabulary used by the shipped report schema."""
    supported = {'$schema', '$id', '$defs', '$ref', 'title', 'description', 'type',
                 'const', 'enum', 'required', 'properties', 'additionalProperties',
                 'items', 'minLength', 'maxLength', 'maxItems', 'pattern',
                 'anyOf', 'allOf', 'not', 'if', 'then', 'else'}
    require(not set(rule) - supported, 'unsupported schema keyword at ' + where)
    if '$ref' in rule:
        ref = rule['$ref']
        require(ref.startswith('#/'), 'external schema reference')
        target = root
        for key in ref[2:].split('/'):
            target = target[key.replace('~1', '/').replace('~0', '~')]
        schema_check(value, target, root, where)
    def accepts(sub):
        try:
            schema_check(value, sub, root, where)
            return True
        except ValueError:
            return False
    for sub in rule.get('allOf', []):
        schema_check(value, sub, root, where)
    if 'anyOf' in rule:
        require(any(accepts(sub) for sub in rule['anyOf']), where + ': anyOf')
    if 'not' in rule:
        require(not accepts(rule['not']), where + ': forbidden value')
    if 'if' in rule:
        branch = 'then' if accepts(rule['if']) else 'else'
        schema_check(value, rule.get(branch, {}), root, where)
    types = {'object': lambda: isinstance(value, dict), 'array': lambda: isinstance(value, list),
             'string': lambda: isinstance(value, str), 'boolean': lambda: type(value) is bool,
             'null': lambda: value is None}
    if 'type' in rule:
        wanted = rule['type'] if isinstance(rule['type'], list) else [rule['type']]
        require(any(types[t]() for t in wanted), where + ': type')
    if 'const' in rule:
        require(type(value) is type(rule['const']) and value == rule['const'], where + ': const')
    if 'enum' in rule:
        require(value in rule['enum'], where + ': enum')
    if isinstance(value, str):
        require(rule.get('minLength', 0) <= len(value) <= rule.get('maxLength', 16777216), where + ': length')
        if 'pattern' in rule:
            require(re.search(rule['pattern'], value) is not None, where + ': pattern')
    if isinstance(value, list):
        require(len(value) <= rule.get('maxItems', 16777216), where + ': items')
        for i, item in enumerate(value):
            schema_check(item, rule.get('items', {}), root, where + '[' + str(i) + ']')
    if isinstance(value, dict):
        require(set(rule.get('required', [])) <= value.keys(), where + ': required member')
        properties = rule.get('properties', {})
        for key, item in value.items():
            if key in properties:
                schema_check(item, properties[key], root, where + '.' + key)
            elif rule.get('additionalProperties') is False:
                raise ValueError(where + ': unexpected member ' + key)
            elif isinstance(rule.get('additionalProperties'), dict):
                schema_check(item, rule['additionalProperties'], root, where + '.' + key)


def accepted_report(path, out, code, *, strict=False, allow_partial=False):
    path = Path(path)
    require(len(out) <= 16777216, 'report exceeds document bound')
    text = out.decode('utf-8')
    V['check_depth'](text, 'report')
    doc = V['parse_json'](text, 'report')
    schema_check(doc, SCHEMA)
    final = path / 'session.json'
    checkpoint = not final.exists()
    if not checkpoint:
        session, summary = V['validate_capture'](path)
        V['compare_report_obj'](doc, session, summary)
    else:
        require(allow_partial and code == 4, 'checkpoint recovery needs partial flag and exit 4')
        metadata = V['read_json_file'](str(path / 'checkpoint.json'), 'checkpoint')
        require(metadata['capture']['finalized'] is False, 'checkpoint finalized')
        require(metadata['capture']['end_reason'] == 'checkpoint', 'checkpoint reason')
        require(V['check_u64'](metadata['capture']['checkpoint_generation'], 'generation') > 0, 'checkpoint generation')
        session = V['check_session'](metadata)
        sealed = metadata['capture']['integrity']
        extent = V['check_u64'](sealed['events_bytes'], 'extent')
        size = (path / 'events.ndjson').stat().st_size
        require(extent <= size, 'prefix exceeds event file')
        with (path / 'events.ndjson').open('rb') as source:
            prefix = source.read(extent)
        require(hashlib.sha256(prefix).hexdigest() == sealed['events_sha256'], 'checkpoint digest')
        require(doc['integrity'] == dict(status='checkpoint_prefix', verified_bytes=str(extent),
                verified_events=sealed['line_count'], unverified_bytes=str(size - extent)), 'checkpoint report integrity')
        with tempfile.NamedTemporaryFile() as stream:
            stream.write(prefix)
            stream.flush()
            summary = V['validate_stream'](session, stream.name)
        projected = copy.deepcopy(doc)
        projected['integrity'] = dict(status='verified', verified_bytes=str(extent), verified_events=sealed['line_count'])
        V['compare_report_obj'](projected, session, summary)
    expected = 4 if checkpoint or strict and doc['verdict']['name'] != 'complete' else 0
    require(code == expected, 'accepted report exit disagrees with finalization/verdict')
    return doc
