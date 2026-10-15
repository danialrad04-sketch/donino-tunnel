"""Pinned HTTPS management, with data-only, locally reconstructed installation.

No remote shell, executable upload, archive extraction, arbitrary file path, URL,
or systemd unit is accepted. The receiver regenerates the expected foreign plan
with its own installed renderer, compares every non-certificate file, then uses
its OWN installed application and installer. Both peers must run identical code.
"""
import asyncio
import hashlib
import json
import os
import re
import secrets
import shutil
import time
from functools import lru_cache
from pathlib import Path

from .config import atomic_json, load_config
from .provision import SAFE_ID, integer, public_address, read_json, strict_fields

PROTOCOL = 'https-v1'
LIMIT = 1024 * 1024
OPERATIONS = ('prepare', 'activate', 'rollback', 'retire', 'cleanup')


@lru_cache(maxsize=1)
def runtime_digest():
    root = Path(__file__).resolve().parent
    digest = hashlib.sha256()
    for path in sorted(root.rglob('*')):
        if not path.is_file() or '__pycache__' in path.parts or path.suffix == '.pyc':
            continue
        digest.update(path.relative_to(root).as_posix().encode() + b'\0')
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def node_files(node):
    return {p.relative_to(node).as_posix(): p.read_text()
            for p in sorted(Path(node).rglob('*')) if p.is_file()}


def validated_node(directory, spec, files):
    """Accept only the exact data files our local plan renderer would generate."""
    from .plan import make_plan
    strict_fields(spec, ['iran', 'foreign', 'services', 'transports', 'experimental',
                        'base_port', 'carrier_base', 'health_port', 'paqet_port',
                        'browser_port', 'panel_port', 'open_ufw', 'paqet_options', 'continuum_options'],
                  ['iran', 'foreign', 'services', 'transports'])
    for key in ('iran', 'foreign'):
        public_address(spec[key])
    if not isinstance(spec['services'], list) or len(spec['services']) > 40:
        raise ValueError('invalid service list')
    for service in spec['services']:
        strict_fields(service, ['id', 'listen', 'target'], ['id', 'listen', 'target'])
        if any(not isinstance(v, str) or len(v) > 300 for v in service.values()):
            raise ValueError('invalid service field')
    if not isinstance(spec['transports'], list) or not all(isinstance(t, str) for t in spec['transports']):
        raise ValueError('invalid transports')
    for key in ('experimental', 'open_ufw'):
        if type(spec.get(key, False)) is not bool:
            raise ValueError('invalid installation switch')
    if not isinstance(files, dict) or not 1 <= len(files) <= 80:
        raise ValueError('invalid node files')
    size = 0
    incoming = directory / 'incoming'
    incoming.mkdir(mode=0o700)
    for name, content in files.items():
        if not isinstance(name, str) or not re.fullmatch(r'(?:node\.json|install\.json|(?:certs|transports|units)/[a-z0-9.-]+)', name):
            raise ValueError('unsupported node file')
        if not isinstance(content, str) or len(content.encode()) > 262144:
            raise ValueError('invalid node file size')
        size += len(content.encode())
        if size > LIMIT:
            raise ValueError('node bundle too large')
        path = incoming / name
        path.parent.mkdir(exist_ok=True, mode=0o700)
        path.write_text(content)
        path.chmod(0o600)

    # Reference rendering needs no CA signing key or new certificates. Copies of
    # received public/leaf material are used ONLY to render the discarded plan.
    def certificates(destination, iran, foreign=None, mux=False):
        destination.mkdir(exist_ok=True)
        for name in ('ca.crt', 'client.crt', 'client.key', 'server.crt', 'server.key',
                     'browser.crt', 'browser.key', 'mux-client.crt', 'mux-client.key'):
            source = name if name in ('ca.crt', 'client.crt', 'client.key') else ('browser.' + name.rsplit('.', 1)[1] if foreign and name.startswith('browser.') else 'client.' + name.rsplit('.', 1)[1])
            path = incoming / 'certs' / source
            if not path.is_file():
                raise ValueError('missing certificate material')
            shutil.copyfile(path, destination / name)

    defaults = {'base_port': 30000, 'carrier_base': 24443, 'health_port': 19090, 'paqet_port': 33434}
    ports = {key: integer(spec.get(key, default), 1024, 65535, key) for key, default in defaults.items()}
    if spec.get('browser_port') is not None:
        integer(spec['browser_port'], 1, 65535, 'browser port')
    reference = directory / 'reference'
    try:
        make_plan(reference, spec['iran'], spec['foreign'], spec['services'], spec['transports'],
                  secrets.token_urlsafe(24), spec.get('experimental', False),
                  ports['base_port'], ports['carrier_base'], ports['health_port'], ports['paqet_port'],
                  spec.get('browser_port'), panel_port=integer(spec.get('panel_port',8090),1,65535,'panel port'), paqet_options=spec.get('paqet_options'),
                  continuum_options=spec.get('continuum_options'), certificate_factory=certificates)
        manifest = read_json(reference / 'foreign/install.json')
        manifest['open_ufw'] = spec.get('open_ufw', False)
        atomic_json(reference / 'foreign/install.json', manifest)
        expected = node_files(reference / 'foreign')
        if set(files) != set(expected):
            raise ValueError('node file set does not match the selected transports')
        normalize = lambda text: re.sub(r'(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])', '0' * 64, text)
        for name, text in expected.items():
            if name.startswith('certs/'):
                # Fixed filenames; TLS libraries/installer validate PEM and keys.
                if not files[name].startswith('-----BEGIN ') or len(files[name]) > 16384:
                    raise ValueError('invalid certificate material')
            elif normalize(text) != normalize(files[name]):
                raise ValueError('node data does not match the locally generated plan: ' + name)
        load_config(incoming / 'node.json')
        return incoming
    finally:
        shutil.rmtree(reference, ignore_errors=True)


class Management:
    def __init__(self, agent, runner_factory=None):
        from .provision import Runner
        self.agent = agent
        self.root = agent.root / 'installations'
        self.root.mkdir(mode=0o700, exist_ok=True)
        self.runner_factory = runner_factory or Runner
        # An uncertain action is never automatically repeated after a restart.
        for path in self.root.glob('*/*/*.json'):
            record = read_json(path, {})
            if record.get('status') == 'running':
                record.update(status='interrupted', error='Management agent restarted; inspect the staged release before retrying.')
                atomic_json(path, record)

    def connection(self, body):
        from . import __version__
        strict_fields(body, ['challenge'])
        challenge = body.get('challenge')
        proof = None
        if challenge is not None:
            if not isinstance(challenge, str) or not re.fullmatch('[0-9a-f]{64}', challenge):
                raise ValueError('invalid management challenge')
            path = self.agent.root / ('check-' + secrets.token_hex(16))
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, 'w') as stream:
                    stream.write(challenge); stream.flush(); os.fsync(stream.fileno())
                proof = hashlib.sha256(path.read_bytes()).hexdigest()
            finally:
                path.unlink(missing_ok=True)
        ready = os.geteuid() == 0 and Path('/run/systemd/system').is_dir() and all(shutil.which(c) for c in ('python3', 'bash', 'systemctl', 'apt-get'))
        return {'management': PROTOCOL, 'version': __version__, 'runtime_digest': runtime_digest(),
                'ready': bool(ready), 'proof': proof, 'time': time.time()}

    def location(self, pair, body):
        strict_fields(body, ['job_id', 'operation', 'runtime_digest', 'spec', 'files'], ['job_id', 'operation'])
        if not isinstance(body['job_id'], str) or not SAFE_ID.fullmatch(body['job_id']):
            raise ValueError('invalid installation ID')
        if body['operation'] not in OPERATIONS:
            raise ValueError('unsupported installation operation')
        return self.root / pair['id'] / body['job_id']

    def status(self, pair, body):
        strict_fields(body, ['job_id', 'operation'], ['job_id', 'operation'])
        directory = self.location(pair, body)
        return read_json(directory / (body['operation'] + '.json'), {'status': 'not_found'})

    async def install(self, pair, body):
        directory = self.location(pair, body)
        op = body['operation']
        strict_fields(body, ['job_id', 'operation', 'runtime_digest', 'spec', 'files'] if op == 'prepare' else ['job_id', 'operation'], ['job_id', 'operation'])
        if op == 'prepare' and (body.get('runtime_digest') != runtime_digest() or not isinstance(body.get('files'), dict) or not isinstance(body.get('spec'), dict)):
            raise ValueError('Management runtimes differ or bundle is invalid; upgrade BOTH nodes before installing.')
        fingerprint = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
        path = directory / (op + '.json')
        with self.agent.lock:
            self.agent.require_pair(pair)
            existing = read_json(path)
            if existing:
                if existing['request_digest'] != fingerprint:
                    raise ValueError('installation ID reused with different data')
                return existing  # Includes running, completed and uncertain actions.
            lease = self.agent.lease()
            if not lease or lease['peer_id'] != pair['id'] or lease['job_id'] != body['job_id']:
                raise ValueError('matching installation lease required')
            if self.agent.action_busy:
                raise ValueError('node is busy')
            if op != 'prepare' and read_json(directory / 'prepare.json', {}).get('status') != 'succeeded':
                # Rollback is still useful if preparation completed on disk just
                # before the process lost its acknowledgement.
                if op not in ('rollback', 'cleanup'):
                    raise ValueError('installation has not been prepared')
            if not directory.exists() and len(list(self.root.glob('*/*'))) >= 40:
                raise ValueError('installation history limit reached; inspect and remove old terminal history locally')
            directory.mkdir(parents=True, mode=0o700, exist_ok=True)
            record = {'job_id': body['job_id'], 'operation': op, 'status': 'running',
                      'request_digest': fingerprint, 'created': time.time()}
            atomic_json(path, record)
            self.agent.action_busy = True

        async def run():
            try:
                await asyncio.to_thread(self.execute, directory, body)
                record['status'] = 'succeeded'
            except Exception as error:
                record.update(status='failed', error=str(error) if isinstance(error, ValueError) else 'Node operation failed; inspect the private installation log.')
            finally:
                record['finished'] = time.time()
                atomic_json(path, record)
                with self.agent.lock:
                    self.agent.action_busy = False
        task = asyncio.create_task(run())
        self.agent.tasks.add(task); task.add_done_callback(self.agent.tasks.discard)
        return record

    def execute(self, directory, body):
        op, job_id = body['operation'], body['job_id']
        release = '/opt/donino-link/releases/control-' + job_id
        runner = self.runner_factory(directory / 'private.log')
        if op == 'prepare':
            from .deploy import build_payload
            incoming = validated_node(directory, body['spec'], body['files'])
            payload = directory / 'payload'
            build_payload(incoming, payload)
            runner.run(['bash', str(payload / 'scripts/install-node.sh'), str(payload), '--prepare', 'control-' + job_id])
        elif op == 'activate':
            runner.run(['bash', release + '/scripts/install-node.sh', release, '--activate', 'control-' + job_id])
        elif op == 'rollback':
            runner.run(['bash', release + '/scripts/rollback.sh', release, '--if-current'])
        elif op == 'retire':
            runner.run([release + '/venv/bin/python', '-m', 'donino_link.host_firewall', 'retire-previous', '--release', release], timeout=30)
        elif op == 'cleanup':
            for name in ('incoming', 'payload'):
                shutil.rmtree(directory / name, ignore_errors=True)


def remote_operation(profile, job_id, operation, **extra):
    """Retry transport loss with the SAME receipt; never duplicate an operation."""
    from aiohttp import ClientError
    from .peer import peer_request
    async def run():
        body = {'job_id': job_id, 'operation': operation, **extra}
        deadline = time.monotonic() + 1900
        failures = 0
        while time.monotonic() < deadline:
            try:
                record = await peer_request(profile, '/install', body)
                while record['status'] == 'running':
                    if time.monotonic() >= deadline:
                        raise ValueError('remote installation deadline exceeded; check its receipt before retrying')
                    await asyncio.sleep(1)
                    record = await peer_request(profile, '/install-status', {'job_id': job_id, 'operation': operation})
                if record['status'] != 'succeeded':
                    raise ValueError(record.get('error', 'remote operation did not succeed'))
                return record
            except (ClientError, OSError, asyncio.TimeoutError):
                failures += 1
                if failures >= 5:
                    raise ValueError('Management channel interrupted; the remote receipt preserves the operation. Check connectivity and job status before retrying.') from None
                await asyncio.sleep(min(failures, 3))
        raise ValueError('remote installation timed out')
    return asyncio.run(run())
