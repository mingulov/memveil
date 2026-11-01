#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Armed test-only conversion-hook feasibility, with memory-only trace sanitization."""
import argparse
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import secrets
import selectors
import shlex
import shutil
import signal
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import owned_region
from owned_qualification import verify_transport

COUNTERS = ('shared_entry', 'private_entry', 'shared_exit', 'private_exit')
LIMIT = 65536
GROUP_GRACE_SECONDS = 10
GROUP_KILL_SECONDS = 5
RESOURCE_SETTLE_SECONDS = 1
RESOURCE_SETTLE_ATTEMPTS = 21
RESOURCE_POLL_SECONDS = 0.05
DIGESTS = {'btf_sha256', 'config_sha256', 'source_evidence_sha256', 'source_review_sha256',
           'bpftrace_sha256', 'bpftool_sha256'}
OWNED_DIGESTS = {'module_sha256', 'oracle_source_sha256', 'safety_review_sha256', 'transport_sha256'}
LABELS = {
    'mv_command_set [memveil_region_oracle]': 'owned',
    'mv_restore [memveil_region_oracle]': 'owned',
    'swiotlb_init_late': 'swiotlb',
    'swiotlb_alloc_tlb': 'swiotlb',
    'swiotlb_free_tlb': 'swiotlb',
    'swiotlb_exit': 'swiotlb',
    'dma_set_decrypted': 'direct_dma',
    'dma_set_encrypted': 'direct_dma',
    'dma_direct_alloc': 'direct_dma',
    'dma_direct_free': 'direct_dma',
}
FRAME = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)(?:\+(?:0x[0-9a-f]+|[0-9]+))?(?: \[([A-Za-z0-9_]+)\])?')


def number(value, signed=False):
    pattern = r'0|-?[1-9][0-9]*' if signed else r'0|[1-9][0-9]*'
    if not isinstance(value, str) or not re.fullmatch(pattern, value):
        raise ValueError('invalid protocol integer')
    result = int(value)
    if not (-(2**31) <= result < 2**31 if signed else 0 <= result < 2**64):
        raise ValueError('protocol integer outside bound')
    return result


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate protocol key')
        value[key] = item
    return value


def decode(raw, limit=LIMIT):
    if len(raw) > limit:
        raise ValueError('document outside bound')
    depth, quoted, escaped = 0, False, False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > 64:
                raise ValueError('document depth outside bound')
        elif byte in (93, 125):
            depth -= 1
    try:
        return json.loads(raw, object_pairs_hook=unique)
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError('invalid protocol document') from None


def identities(stream):
    """Keep only allowlisted names/modules; discard each kallsyms line immediately."""
    candidates = {label.split(' ', 1)[0] for label in LABELS}
    found = {}
    for index, line in enumerate(stream):
        if index >= 2000000 or len(line) > 4096:
            raise ValueError('symbol source outside bound')
        fields = line.split()
        if len(fields) not in (3, 4) or fields[2] not in candidates or fields[1] not in ('t', 'T'):
            continue
        name = fields[2]
        label = name if len(fields) == 3 else name + ' ' + fields[3]
        if name in found:
            found[name] = None
        else:
            found[name] = label if label in LABELS else None
    return found


def current_identities():
    with open('/proc/kallsyms') as stream:
        return identities(stream)


def classify(stack, names=None):
    frames = [line.strip() for line in stack.splitlines() if line.strip()]
    if len(frames) > 16:
        raise ValueError('caller frame bound exceeded')
    labels = set()
    for frame in frames:
        match = FRAME.fullmatch(frame)
        if not match:
            continue
        name, module = match.groups()
        label = name + (f' [{module}]' if module else '')
        if names is not None:
            resolved = names.get(name)
            if resolved is None or (module and label != resolved):
                continue
            label = resolved
        if label in LABELS:
            labels.add(label)
    classes = {LABELS[label] for label in labels}
    quality = ('truncated' if len(frames) == 16 else 'ambiguous' if len(classes) > 1
               else next(iter(classes)) if classes else 'unresolved')
    return quality, sorted(labels)


class Trace:
    def __init__(self, hook, callers, owned=False, resolver=None, announce=False):
        self.hook, self.callers, self.owned, self.resolver = hook, callers, owned, resolver
        self.ready = False
        self.ready_ns = None
        self.attached = False
        self.terminal = None
        self.counts = dict.fromkeys(COUNTERS, 0)
        self.classes = dict.fromkeys(('owned', 'swiotlb', 'direct_dma', 'unresolved', 'ambiguous', 'truncated'), 0)
        self.labels = dict.fromkeys(LABELS, 0)
        self.rows = []
        self.results = {'success': 0, 'failure': 0}
        self.requested_pages = {'shared': 0, 'private': 0}
        self.announce = announce

    def feed(self, raw):
        if len(raw) > LIMIT or not raw.endswith(b'\n'):
            raise ValueError('trace line outside framing bound')
        item = decode(raw)
        if isinstance(item, dict) and set(item) == {'type', 'count', 'data'} and item['type'] == 'attached_probes':
            if (not self.attached and type(item['count']) is int and item['count'] == 6 and
                    item['data'] == {'probes': 6} and type(item['data']['probes']) is int):
                self.attached = True
                return
        if not isinstance(item, dict) or set(item) != {'type', 'data'} or item['type'] != 'printf' or not isinstance(item['data'], str):
            raise ValueError('unexpected trace output or loss')
        text = item['data']
        if not text.endswith('\n') or not text.startswith('MVJ1|') or self.terminal is not None:
            raise ValueError('invalid trace protocol state')
        fields = text[:-1].split('|', 4)
        if fields == ['MVJ1', 'ready'] and not self.ready:
            if not self.attached:
                raise ValueError('attachment receipt missing before readiness')
            self.ready = True
            self.ready_ns = time.monotonic_ns()
            if self.announce:
                print('READY: bounded observation window; baseline remains unknown', flush=True)
            return
        if not self.ready:
            raise ValueError('trace readiness missing')
        if fields[1] == 'counts':
            values = text[:-1].split('|')[2:]
            if len(values) != 4:
                raise ValueError('invalid counter record')
            self.terminal = dict(zip(COUNTERS, map(number, values)))
            return
        if len(fields) != 5 or fields[1] not in ('entry', 'exit') or fields[2] not in ('shared', 'private'):
            raise ValueError('invalid trace record')
        _, kind, direction, pages, payload = fields
        if pages == '-' and self.hook == 'kprobe' and kind == 'exit':
            count = None
        else:
            count = number(pages, signed=True)
            if count <= 0:
                raise ValueError('nonpositive request pages')
        key = direction + '_' + kind
        self.counts[key] += 1
        caller = None
        if kind == 'entry':
            if self.callers:
                quality, labels = classify(payload, self.resolver() if self.resolver else None)
                caller = (quality, tuple(labels))
                self.classes[quality] += 1
                for label in labels:
                    self.labels[label] += 1
            elif payload != 'disabled':
                raise ValueError('caller output while disabled')
            self.requested_pages[direction] += count
            if self.requested_pages[direction] >= 2**64:
                raise ValueError('requested page aggregate outside bound')
            result = None
        else:
            result = number(payload, signed=True)
            self.results['success' if result == 0 else 'failure'] += 1
        if self.owned:
            if len(self.rows) >= 4:
                raise ValueError('owned observation bound exceeded')
            self.rows.append((kind, direction, count, result, caller))

    def finish(self):
        if not self.ready or self.terminal is None or self.counts != self.terminal:
            raise ValueError('missing terminal or independent count mismatch')
        total = sum(self.counts[key] for key in ('shared_entry', 'private_entry'))
        classified = sum(self.classes[key] for key in ('owned', 'swiotlb', 'direct_dma'))
        return {'counts': {k: str(v) for k, v in self.counts.items()},
                'requested_pages': {k: str(v) for k, v in self.requested_pages.items()},
                'native_results': {k: str(v) for k, v in self.results.items()},
                'caller_quality': {'status': 'enabled' if self.callers else 'disabled',
                                   'classified': str(classified), 'total': str(total),
                                   'target_met': 100 * classified >= 95 * total if self.callers and total else None,
                                   'classes': {k: str(v) for k, v in self.classes.items()}},
                'labels': {k: str(v) for k, v in self.labels.items() if v},
                'window_membership': 'owned_serial_only' if self.owned else 'unproved_global_boundaries',
                'shared_hook_blind_spot': True, 'state_claim': 'unavailable'}


def compare_owned(trace, rows):
    expected = []
    if (not isinstance(rows, list) or len(rows) != 2 or
            any(not isinstance(r, list) or len(r) != 3 for r in rows)):
        raise ValueError('owned ledger invalid')
    for index, row in enumerate(rows):
        direction, pages, result = row
        if direction != ('shared' if index == 0 else 'private') or type(result) is not int or result != 0 or not 1 <= number(pages) <= 256:
            raise ValueError('owned native sequence failed')
        expected.extend([('entry', direction, int(pages), None),
                         ('exit', direction, int(pages) if trace.hook == 'fentry' else None, result)])
    if len(rows) != 2 or [row[:4] for row in trace.rows] != expected:
        raise ValueError('owned observation/ledger mismatch')
    if trace.callers:
        for entry in trace.rows[::2]:
            caller = entry[4]
            if (caller is None or caller[0] != 'owned' or not caller[1] or
                    any(LABELS.get(label) != 'owned' for label in caller[1])):
                raise ValueError('owned caller identity missing or unproved')


def program(hook, callers=False, owned=False):
    if hook not in ('fentry', 'kprobe'):
        raise ValueError('unsupported hook mode')
    source = '''config = { max_map_keys=64; max_probes=8; max_bpf_progs=8;
 perf_rb_pages=64; log_size=65536; print_maps_on_exit=0; missing_probes=error;
 show_debug_info=0; }
BEGIN { printf("MVJ1|ready\\n"); }
'''
    predicate = '/pid == cpid/' if owned else ''
    for direction, symbol in [('shared', 'set_memory_decrypted'), ('private', 'set_memory_encrypted')]:
        pages = 'args.numpages' if hook == 'fentry' else '(int32)arg1'
        stack = 'kstack(bpftrace, 16)' if callers else '"disabled"'
        source += f'{hook}:{symbol} {predicate} {{ @{direction}_entry = count(); printf("MVJ1|entry|{direction}|%d|%s\\n", {pages}, {stack}); }}\n'
        end = 'fexit' if hook == 'fentry' else 'kretprobe'
        fmt = '%d' if hook == 'fentry' else '-'
        argument = 'args.numpages, ' if hook == 'fentry' else ''
        source += f'{end}:{symbol} {predicate} {{ @{direction}_exit = count(); printf("MVJ1|exit|{direction}|{fmt}|%d\\n", {argument}(int32)retval); }}\n'
    source += 'END { printf("MVJ1|counts|%llu|%llu|%llu|%llu\\n", ' + ', '.join('@' + k for k in COUNTERS) + '); }\n'
    return source


def group_absent(pgid):
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return True
    return False


def _cleanup_group(child):
    """Own descendants until the group is absent, independently of leader exit."""
    failed = False
    for signum, seconds in ((signal.SIGINT, GROUP_GRACE_SECONDS),
                            (signal.SIGKILL, GROUP_KILL_SECONDS)):
        try:
            child.poll()
            if group_absent(child.pid):
                break
            os.killpg(child.pid, signum)
        except ProcessLookupError:
            pass
        except (OSError, KeyboardInterrupt):
            failed = True
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                child.poll()
                if group_absent(child.pid):
                    break
                time.sleep(0.02)
            except (OSError, KeyboardInterrupt):
                failed = True
    try:
        child.wait(timeout=0)
        return group_absent(child.pid) and not failed
    except (OSError, KeyboardInterrupt, subprocess.TimeoutExpired):
        return False


def cleanup_group(child):
    interrupted = False
    previous = {}

    def latch(_signum, _frame):
        nonlocal interrupted
        interrupted = True

    try:
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            previous[signum] = signal.signal(signum, latch)
        clean = _cleanup_group(child)
        return clean and not interrupted
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def pipe(argv, trace, timeout):
    """Never pass diagnostic bytes to files, exceptions, or the parent terminal."""
    environment = {k: v for k, v in os.environ.items() if not k.startswith(('BPFTRACE_', '__BPFTRACE_', 'PYTHON'))}
    child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, env=environment)
    trace.child_pid = child.pid
    trace.process_cleanup = 'unproved'
    poll = None
    pending = bytearray()
    diagnostic = bytearray()
    total = 0
    deadline = time.monotonic() + timeout
    try:
        poll = selectors.DefaultSelector()
        poll.register(child.stdout, selectors.EVENT_READ, 'stdout')
        poll.register(child.stderr, selectors.EVENT_READ, 'stderr')
        while poll.get_map():
            if time.monotonic() >= deadline:
                raise ValueError('trace deadline exceeded')
            for key, _ in poll.select(0.1):
                chunk = os.read(key.fd, 4096)
                if not chunk:
                    poll.unregister(key.fileobj)
                    continue
                total += len(chunk)
                if total > 16 * 1024 * 1024:
                    raise ValueError('trace transport bound exceeded')
                if key.data == 'stderr':
                    diagnostic.extend(chunk)
                    if len(diagnostic) > LIMIT:
                        raise ValueError('diagnostic bound exceeded')
                    continue
                pending.extend(chunk)
                while b'\n' in pending:
                    end = pending.index(b'\n') + 1
                    trace.feed(bytes(pending[:end]))
                    del pending[:end]
                if len(pending) > LIMIT:
                    raise ValueError('trace line bound exceeded')
        if pending:
            raise ValueError('partial trace line')
        rc = child.wait(timeout=1)
        lower = bytes(diagnostic).lower()
        permission = b'operation not permitted' in lower or b'permission denied' in lower
        probe_phase = any(marker in lower for marker in (b'failed to attach', b'error attaching probe',
                         b'failed to load bpf', b'bpf_prog_load', b'bpf_map_create', b'failed to create map'))
        reason = ('none' if not lower.strip() else 'permission' if permission and probe_phase
                  else 'missing_hook' if b'no probes to attach' in lower or b'not traceable' in lower
                  else 'diagnostic')
        return rc, reason
    finally:
        primary = sys.exception()
        try:
            clean = cleanup_group(child)
        except (OSError, KeyboardInterrupt):
            clean = False
        finally:
            if poll is not None:
                poll.close()
            child.stdout.close()
            child.stderr.close()
        trace.process_cleanup = 'verified' if clean else 'unproved'
        trace.process_exit = child.returncode
        if not clean:
            if primary is not None:
                primary.add_note('owned process-group cleanup unproved')
            else:
                raise ValueError('owned process-group cleanup unproved')


def save(path, value):
    data = (json.dumps(value, sort_keys=True) + '\n').encode()
    if len(data) > LIMIT:
        raise ValueError('receipt outside bound')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        import stat
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError('regular input required')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            return decode(stream.read(LIMIT + 1))
    finally:
        os.close(fd)


def validate_manifest(value, owned):
    fields = {'schema', 'platform', 'kernel_release', 'lockdown', 'owned'} | DIGESTS
    if not isinstance(value, dict) or set(value) != fields or value['schema'] != 'memveil-journal-spike-input/1':
        raise ValueError('invalid input manifest fields')
    if (value['platform'] not in ('ordinary', 'sev-snp') or
            value['lockdown'] not in ('none', 'integrity', 'confidentiality') or
            not isinstance(value['kernel_release'], str) or
            not re.fullmatch(r'[A-Za-z0-9_.+-]{1,128}', value['kernel_release'])):
        raise ValueError('invalid observed cell identity')
    for key in DIGESTS:
        if not isinstance(value[key], str) or not re.fullmatch('[0-9a-f]{64}', value[key]):
            raise ValueError('invalid prerequisite digest')
    native = value['owned']
    if not owned and native is None:
        return
    if not isinstance(native, dict) or set(native) != OWNED_DIGESTS | {'restore_contract'}:
        raise ValueError('owned safety and transport prerequisites required')
    if native['restore_contract'] != 'whole_range_native_success':
        raise ValueError('owned whole-range restoration review required')
    for key in OWNED_DIGESTS:
        if not isinstance(native[key], str) or not re.fullmatch('[0-9a-f]{64}', native[key]):
            raise ValueError('invalid owned prerequisite digest')


class Bytes:
    def __init__(self):
        self.data = bytearray()

    def feed(self, raw):
        self.data.extend(raw)
        if len(self.data) > 1024 * 1024:
            raise ValueError('tool metadata outside bound')


def metadata(argv):
    sink = Bytes()
    rc, diagnostic = pipe(argv, sink, 10)
    if rc or diagnostic != 'none':
        raise ValueError('metadata tool unavailable')
    return bytes(sink.data)


def resources():
    identity = os.uname()
    if (identity.sysname != 'Linux' or identity.machine != 'x86_64' or
            ctypes.sizeof(ctypes.c_void_p) != 8 or ctypes.sizeof(ctypes.c_long) != 8):
        raise ValueError('resource inventory requires Linux x86-64 userspace')
    syscall = ctypes.CDLL(None, use_errno=True).syscall
    syscall.restype = ctypes.c_long
    syscall.argtypes = (ctypes.c_long, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint)
    snapshot = {}
    for kind, command in (('prog', 11), ('map', 12), ('link', 31)):
        ids = set()
        start = 0
        for _ in range(4097):
            attr = (ctypes.c_uint32 * 3)(start, 0, 0)
            ctypes.set_errno(0)
            result = syscall(321, command, ctypes.byref(attr), ctypes.sizeof(attr))
            if result == -1:
                if ctypes.get_errno() == errno.ENOENT:
                    break
                raise ValueError('resource inventory unavailable')
            if result != 0 or attr[1] <= start:
                raise ValueError('invalid resource identifier')
            if len(ids) == 4096:
                raise ValueError('resource inventory outside bound')
            start = attr[1]
            ids.add(start)
        snapshot[kind] = ids
    return snapshot


def settle_resources(before, trace):
    if getattr(trace, 'process_cleanup', None) != 'verified':
        return 'process_unproved'
    deadline = time.monotonic() + RESOURCE_SETTLE_SECONDS
    for attempt in range(RESOURCE_SETTLE_ATTEMPTS):
        after = resources()
        remaining = deadline - time.monotonic()
        if remaining < 0:
            break
        if before == after and group_absent(trace.child_pid) and not owned_region.PARAMS.parent.exists():
            return 'verified'
        if remaining <= 0 or attempt + 1 == RESOURCE_SETTLE_ATTEMPTS:
            break
        time.sleep(min(RESOURCE_POLL_SECONDS, remaining))
    return 'timeout'


def verdict(mode, rc, diagnostic, ready, cleanup):
    if not cleanup:
        raise ValueError('independent cleanup unproved')
    if mode == 'refusal':
        if rc == 0 or ready or diagnostic not in ('permission', 'missing_hook'):
            raise ValueError('expected tracer refusal boundary not reached')
        return 'REFUSAL_OBSERVED'
    if rc or diagnostic != 'none' or not ready:
        raise ValueError('required positive tracer command failed')
    return 'OBSERVED'


def preflight(args):
    if os.environ.get('MEMVEIL_JOURNAL_SPIKE_GUEST') != '1' or os.geteuid() != 0:
        raise ValueError('assigned disposable guest root required')
    if os.uname().machine != 'x86_64' or os.sysconf('SC_PAGE_SIZE') != 4096:
        raise ValueError('source-reviewed x86-64 4 KiB cell required')
    if not args.manifest or not args.config or not args.source_evidence or not args.source_review:
        raise ValueError('observed identity and reviewed source inputs required')
    manifest = read(args.manifest)
    validate_manifest(manifest, args.mode == 'owned')
    bpftrace, bpftool = shutil.which('bpftrace'), shutil.which('bpftool')
    if not bpftrace or not bpftool:
        raise ValueError('pinned tracing tools required')
    bindings = {'btf_sha256': Path('/sys/kernel/btf/vmlinux'), 'config_sha256': args.config,
                'source_evidence_sha256': args.source_evidence, 'source_review_sha256': args.source_review,
                'bpftrace_sha256': bpftrace, 'bpftool_sha256': bpftool}
    if os.uname().release != manifest['kernel_release']:
        raise ValueError('booted release identity mismatch')
    for key, path in bindings.items():
        if owned_region.digest(path) != manifest[key]:
            raise ValueError('source or environment digest mismatch')
    lock = read(Path(__file__).resolve().parents[2] / 'vm' / 'kernels.lock.json')
    for tool in (bpftrace, bpftool):
        expected = lock['tools'][Path(tool).name]
        version = metadata([tool, '--version']).decode('ascii').strip()
        if version.splitlines()[0] != expected:
            raise ValueError('tool version differs from repository lock')
    lockdown = Path('/sys/kernel/security/lockdown')
    if not lockdown.is_file():
        raise ValueError('effective lockdown unavailable')
    active = re.findall(r'\[(none|integrity|confidentiality)\]', lockdown.read_text())
    if active != [manifest['lockdown']]:
        raise ValueError('effective lockdown mismatch')
    if args.output.exists() or args.output.is_symlink():
        raise ValueError('fresh output directory required')
    if owned_region.PARAMS.parent.exists():
        raise ValueError('existing oracle module is not owned by this run')
    if args.mode == 'owned':
        if not args.module or not args.safety_review or not args.transport:
            raise ValueError('reviewed oracle and ordinary transport required')
        native = manifest['owned']
        for key, path in [('module_sha256', args.module), ('safety_review_sha256', args.safety_review),
                          ('oracle_source_sha256', Path(__file__).resolve().parents[2] / 'kernel' / 'memveil_region_oracle.c')]:
            if owned_region.digest(path) != native[key]:
                raise ValueError('owned prerequisite identity mismatch')
        verify_transport(args.transport, native)
    return manifest, bpftrace, bpftool


def run(args):
    manifest, tracer, _bpftool = preflight(args)
    before = resources()
    args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    trace = Trace(args.hook, args.callers, args.mode == 'owned', current_identities if args.callers else None, True)
    source = program(args.hook, args.callers, args.mode == 'owned')
    epoch = secrets.randbelow(2**64 - 1) + 1
    native_path = args.output / 'native.json'
    child = [sys.executable, str(Path(__file__).resolve()), '--idle-worker', str(args.seconds)]
    if args.mode == 'owned':
        child = [sys.executable, str(Path(owned_region.__file__).resolve()), '--worker',
                 '--module', str(args.module.resolve()), '--output', str(native_path.resolve()),
                 '--epoch', str(epoch), '--pages', str(args.pages), '--retain-seconds', str(args.retain_seconds)]
    receipt = {'schema': 'memveil-journal-spike/1', 'status': 'FAIL', 'scope': 'test_only_provisional',
               'admission': 'not_granted', 'mode': args.mode, 'hook': args.hook,
               'input': manifest, 'input_sha256': owned_region.digest(args.manifest),
               'runner_sha256': owned_region.digest(__file__),
               'probe_sha256': hashlib.sha256(source.encode()).hexdigest(),
               'seconds': str(args.seconds), 'callers': args.callers,
               'cleanup': 'unproved', 'resource_settlement': 'not_started',
               'tracer_exit': None, 'diagnostic': 'none',
               'baseline': 'unknown', 'state_claim': 'unavailable'}
    failed = True
    started = time.monotonic_ns()
    try:
        os.environ['MEMVEIL_OWNED_REGION_GUEST'] = '1'
        rc, diagnostic = pipe([tracer, '-f', 'json', '-e', source, '-c', shlex.join(child)], trace, args.seconds + 45)
        receipt['tracer_exit'], receipt['diagnostic'] = rc, diagnostic
        receipt['resource_settlement'] = 'unproved'
        receipt['resource_settlement'] = settle_resources(before, trace)
        clean = receipt['resource_settlement'] == 'verified'
        receipt['cleanup'] = 'verified' if clean else 'unproved'
        receipt['status'] = verdict(args.mode, rc, diagnostic, trace.ready, clean)
        if args.mode != 'refusal':
            receipt['observation'] = trace.finish()
        if args.mode == 'owned':
            native = read(native_path)
            expected = {'epoch', 'pages', 'rows', 'cleanup', 'retained_seconds', 'status'}
            if (set(native) != expected or native['status'] != 'PASS' or native['cleanup'] != 'unloaded' or
                    native['epoch'] != str(epoch) or native['pages'] != str(args.pages) or
                    native['retained_seconds'] != str(args.retain_seconds)):
                raise ValueError('owned worker identity or cleanup failed')
            compare_owned(trace, native['rows'])
            receipt['native_sha256'] = owned_region.digest(native_path)
        failed = False
    except (OSError, ValueError, subprocess.SubprocessError, KeyboardInterrupt):
        receipt['status'] = 'FAIL'
        receipt['failure'] = 'prerequisite_transport_native_or_cleanup_unproved'
    finally:
        receipt['process_cleanup'] = getattr(trace, 'process_cleanup', 'not_started')
        if receipt['tracer_exit'] is None:
            receipt['tracer_exit'] = getattr(trace, 'process_exit', None)
        if failed:
            try:
                if receipt['resource_settlement'] == 'not_started':
                    receipt['resource_settlement'] = 'unproved'
                    receipt['resource_settlement'] = settle_resources(before, trace)
                receipt['cleanup'] = ('verified_resources_only' if resources() == before and
                                      not owned_region.PARAMS.parent.exists() and
                                      receipt['process_cleanup'] == 'verified' and group_absent(trace.child_pid)
                                      else 'unproved_reboot_required')
            except (OSError, ValueError, subprocess.SubprocessError):
                receipt['cleanup'] = 'unproved_reboot_required'
        receipt['maxrss_kib'] = str(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
        receipt['children_maxrss_kib'] = str(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)
        receipt['bpf_memory'] = 'not_measured'
        receipt['supervisor_monotonic_ns'] = {'start': str(started),
                                              'ready': str(trace.ready_ns) if trace.ready_ns is not None else None,
                                              'finish': str(time.monotonic_ns())}
        save(args.output / 'receipt.json', receipt)
    print('FAIL: preserve sanitized receipts; never force unload' if failed else receipt['status'] + ': provisional request observations only')
    return 1 if failed else 0


def main():
    if len(sys.argv) == 3 and sys.argv[1] == '--idle-worker':
        seconds = number(sys.argv[2])
        if not 1 <= seconds <= 60:
            return 2
        time.sleep(seconds)
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arm', action='store_true')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--manifest', type=Path)
    parser.add_argument('--config', type=Path)
    parser.add_argument('--source-evidence', type=Path)
    parser.add_argument('--source-review', type=Path)
    parser.add_argument('--mode', choices=('observe', 'owned', 'refusal'), default='observe')
    parser.add_argument('--hook', choices=('fentry', 'kprobe'), default='fentry')
    parser.add_argument('--callers', action='store_true')
    parser.add_argument('--seconds', type=int, default=60)
    parser.add_argument('--module', type=Path)
    parser.add_argument('--safety-review', type=Path)
    parser.add_argument('--transport', type=Path)
    parser.add_argument('--pages', type=int, default=3)
    parser.add_argument('--retain-seconds', type=int, default=1)
    args = parser.parse_args()
    if not args.arm:
        print('SKIPPED: explicit --arm in an assigned disposable guest is required')
        return 77
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        def interrupt(_signum, _frame):
            raise KeyboardInterrupt
        for signum in (signal.SIGTERM, signal.SIGHUP):
            signal.signal(signum, interrupt)
        if not 1 <= args.seconds <= 60 or not 1 <= args.pages <= 256 or not 0 <= args.retain_seconds <= 3:
            raise ValueError('workload outside bounded limits')
        return run(args)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, KeyboardInterrupt):
        print('FAIL: observed guest identity, tools, source review, ownership or transport prerequisites unmet', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
