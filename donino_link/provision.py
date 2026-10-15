"""Root-only, typed two-node installation service behind a Unix socket.

The public panel stays unprivileged. No submitted command, path, key or URL is
executed. The worker owns its SSH key, pinned hosts, private plans and journal.
"""
import asyncio
import base64
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import tarfile
import tempfile
import threading
import time
from pathlib import Path
from aiohttp import web,ClientError
from .config import atomic_json, endpoint, load_config, loopback
from .deploy import build_payload
from .plan import make_plan, TRANSPORTS, EXPERIMENTAL

ROOT = Path('/var/lib/donino-control')
SOCKET = Path('/run/donino-control/control.sock')
LIVE = Path('/etc/donino-link/current/node.json')
OPT = '/opt/donino-link'
SAFE_ID = re.compile(r'^[0-9a-f]{32}$')


def read_json(path, default=None):
    return json.loads(Path(path).read_text()) if Path(path).exists() else default


def strict_fields(body, allowed, required=()):
    if not isinstance(body, dict) or set(body) - set(allowed) or set(required) - set(body):
        raise ValueError('invalid or unknown fields')


def integer(value, lo, hi, name):
    if isinstance(value, bool) or not isinstance(value, int) or not lo <= value <= hi:
        raise ValueError(f'invalid {name}')
    return value


def public_address(value):
    if not isinstance(value, str) or len(value) > 253:
        raise ValueError('invalid server address')
    if re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9.-]*', value):
        return value
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise ValueError('use an IP address or DNS name without a scheme or port') from None


def pinned_line(scan, host, port, fingerprint):
    """A scan is accepted only after comparing a separately obtained SHA256 pin."""
    if not isinstance(fingerprint,str) or not re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', fingerprint):
        raise ValueError('expected SHA256 SSH host fingerprint')
    label = host if port == 22 else f'[{host}]:{port}'
    for line in scan.splitlines():
        parts = line.split()
        if len(parts) != 3 or parts[1] not in ('ssh-ed25519', 'ecdsa-sha2-nistp256', 'ssh-rsa'):
            continue
        try:
            raw = base64.b64decode(parts[2], validate=True)
        except ValueError:
            continue
        actual = 'SHA256:' + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip('=')
        if secrets.compare_digest(actual, fingerprint):
            return f'{label} {parts[1]} {parts[2]}\n'
    raise ValueError('SSH host key does not match the trusted fingerprint')


def scan_pinned_key(host,port,fingerprint,key_type=None):
    if key_type is not None and key_type not in ('ed25519','ecdsa','rsa'):
        raise ValueError('invalid SSH host key type')
    if not isinstance(fingerprint,str) or not re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}',fingerprint):
        raise ValueError('expected SHA256 SSH host fingerprint')
    for attempt in range(3):
        result=subprocess.run(['ssh-keyscan','-T','5','-p',str(port),'-t',key_type or 'ed25519,ecdsa,rsa',host],capture_output=True,text=True,timeout=25)
        # A received key is checked immediately. Never retry a different key
        # into acceptance; only a scan with no supported key can be retried.
        if any(len(parts)==3 and parts[1] in ('ssh-ed25519','ecdsa-sha2-nistp256','ssh-rsa') for line in result.stdout.splitlines() for parts in [line.split()]):
            return pinned_line(result.stdout,host,port,fingerprint)
        if attempt<2:time.sleep(.25*(attempt+1))
    raise ValueError('SSH host key scan returned no key; check SSH reachability and rate limits')


class CommandFailure(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(f'command failed (exit {code}); private worker log has details')


class Runner:
    def __init__(self, log):
        self.log = Path(log)

    def run(self, args, data=None, timeout=1800):
        # Only fixed/generated argv; never a submitted shell fragment.
        result = subprocess.run(args, input=data, capture_output=True, timeout=timeout)
        with self.log.open('ab') as f:
            os.chmod(self.log, 0o600)
            f.write(result.stdout[-512*1024:]); f.write(result.stderr[-512*1024:])
        if result.returncode:
            raise CommandFailure(result.returncode)
        return result.stdout.decode(errors='replace')


class Coordinator:
    """Both nodes prepare before either activates. Every side effect is journaled."""
    def __init__(self, worker, runner):
        self.worker, self.runner = worker, runner

    def ssh(self, profile, command, data=None, timeout=1800):
        return self.runner.run(self.worker.ssh_args(profile) + [command], data, timeout)

    def remote(self, profile, job, operation, **extra):
        from .management import remote_operation
        return remote_operation(profile, job['id'], operation, **extra)

    def execute(self, job):
        w, r = self.worker, self.runner
        directory = w.root/'plans'/job['plan_id']
        meta = read_json(directory/'control.json')
        profile = w.profile(meta['profile_id'])
        summary = read_json(directory/'plan.json')
        stage = w.root/'jobs'/job['id']/'payload'
        stage.mkdir(mode=0o700)
        remote = '/var/tmp/donino-control-' + job['id']
        release = '/opt/donino-link/releases/control-' + job['id']
        job['release'] = release
        w.save_job(job)
        leased=False
        agent_channel=bool(profile.get('agent_token'))
        try:
            w.event(job, 'preflight', 'running', 'Checking both servers before making changes')
            if agent_channel:
                connection=w.check_connection({'profile_id':profile['id']})
                if not connection['ready']:raise ValueError('Foreign root agent or systemd prerequisites are not ready')
                if not connection['runtime_match']:raise ValueError('Upgrade BOTH nodes to the same runtime before installing')
            else:
                self.ssh(profile, "test \"$(id -u)\" -eq 0 && test -d /run/systemd/system && command -v python3 && command -v apt-get", timeout=30)
            r.run(['test', '-d', '/run/systemd/system'], timeout=5)
            w.event(job, 'preflight', 'done', 'Pinned HTTPS identity and management write/read verified' if agent_channel else 'SSH pin and root access verified (manual legacy connection)')
            if profile.get('agent_token'):
                from .peer import peer_request
                asyncio.run(peer_request(profile,'/lease',{'job_id':job['id']}));leased=True
            # Use the same frozen node bundles that the operator reviewed.
            for role in ['foreign', 'iran']:
                w.event(job, 'prepare-'+role, 'running', 'Preparing prerequisites and verified engine binaries')
                if leased:asyncio.run(peer_request(profile,'/lease',{'job_id':job['id']}))
                payload = stage/role
                if role == 'foreign' and agent_channel:
                    from .management import node_files,runtime_digest
                    spec={k:v for k,v in meta['spec'].items() if k not in ('profile_id','paqet_keep_secrets')}
                    spec['panel_port']=endpoint(load_config(w.live)['panel']['listen'])[1]
                    self.remote(profile,job,'prepare',spec=spec,files=node_files(directory/'foreign'),runtime_digest=runtime_digest())
                elif role == 'foreign':
                    build_payload(directory/role, payload)
                    archive = stage/'foreign.tar.gz'
                    with tarfile.open(archive, 'w:gz') as tar:
                        for item in payload.iterdir(): tar.add(item, arcname=item.name)
                    self.ssh(profile, f'mkdir -m 700 {remote}')
                    with archive.open('rb') as f:
                        self.ssh(profile, f'tar -xzf - -C {remote}', f.read())
                    self.ssh(profile, f'bash {remote}/scripts/install-node.sh {remote} --prepare control-{job["id"]}')
                else:
                    build_payload(directory/role, payload)
                    r.run(['bash', str(payload/'scripts/install-node.sh'), str(payload), '--prepare', 'control-'+job['id']])
                job['prepared'].append(role); w.save_job(job)
                w.event(job, 'prepare-'+role, 'done', 'Prepared; active installation has not switched')
            for role in ['foreign', 'iran']:
                if leased:asyncio.run(peer_request(profile,'/lease',{'job_id':job['id']}))
                # Save intent first: restart recovery can roll back a half-completed activation.
                job['activating'] = role; w.save_job(job)
                w.event(job, 'activate-'+role, 'running', 'Activating staged units and configuration')
                if role == 'foreign':
                    if agent_channel:self.remote(profile,job,'activate')
                    else:self.ssh(profile, f'bash {release}/scripts/install-node.sh {release} --activate control-{job["id"]}')
                else:
                    r.run(['bash', release+'/scripts/install-node.sh', release, '--activate', 'control-'+job['id']])
                job['activated'].append(role); job['activating'] = None; w.save_job(job)
                w.event(job, 'activate-'+role, 'done', 'Services started')
            w.event(job, 'verify', 'running', 'Testing every selected carrier with signed round-trip probes')
            from .cli import doctor
            rows = []
            for attempt in range(20):
                live_config = load_config(w.live)
                expected = read_json(directory/'iran/node.json')
                if live_config['health_key'] != expected['health_key'] or [p['id'] for p in live_config['paths']] != summary['transports']:
                    raise RuntimeError('Live configuration changed during installation; stopping verification')
                rows = asyncio.run(doctor(live_config))
                job['probes'] = rows; w.save_job(job)
                if len(rows) == len(summary['transports']) and all(row['ok'] and all(row.get('services', {}).values()) for row in rows):
                    break
                time.sleep(2)
            else:
                raise RuntimeError('Some selected paths, TCP destinations or UDP relays failed. Check the listed provider firewall ports and origin services.')
            job['probes'] = rows
            w.event(job, 'verify', 'done', 'All selected paths, TCP destinations and UDP relays passed')
            job['status'] = 'succeeded'
            w.event(job, 'complete', 'done', 'Installation complete; sign in again after the panel restart')
            for role in ['foreign','iran']:
                try:
                    command = ['/opt/donino-link/current/venv/bin/python','-m','donino_link.host_firewall','retire-previous','--release',release]
                    if role=='iran':r.run(command,timeout=30)
                    elif agent_channel:self.remote(profile,job,'retire')
                    else:self.ssh(profile,' '.join(command),timeout=30)
                except Exception:
                    w.event(job,'firewall-cleanup-'+role,'warning','Installation succeeded; old owned UFW rules need manual cleanup')
        except Exception as error:
            job['error'] = str(error) if isinstance(error, (ValueError, RuntimeError)) else type(error).__name__
            self.rollback(job, profile)
            if job['status'] != 'rollback_failed': job['status'] = 'failed'
            w.event(job, 'failure', 'failed', job['error'])
        finally:
            try:
                if agent_channel and leased:self.remote(profile,job,'cleanup')
                elif not agent_channel:self.ssh(profile, f'rm -rf -- {remote}', timeout=20)
            except Exception: pass
            if leased:
                try:asyncio.run(peer_request(profile,'/release',{'job_id':job['id']}))
                except Exception:pass
            shutil.rmtree(stage, ignore_errors=True)
            w.save_job(job)

    def rollback(self, job, profile):
        # The release guard makes recovery/repeated rollback idempotent and cannot
        # roll back a later operator deployment or the installer's own restoration.
        roles = list(job['activated'])
        if job.get('activating') and job['activating'] not in roles: roles.append(job['activating'])
        for role in reversed(roles):
            self.worker.event(job, 'rollback-'+role, 'running', 'Restoring the preceding release')
            try:
                command = ['bash', job['release']+'/scripts/rollback.sh', job['release'], '--if-current']
                if role == 'iran': self.runner.run(command)
                elif profile.get('agent_token'):self.remote(profile,job,'rollback')
                else: self.ssh(profile, ' '.join(command))
                self.worker.event(job, 'rollback-'+role, 'done', 'Previous release restored or already active')
            except Exception:
                job['status'] = 'rollback_failed'
                self.worker.event(job, 'rollback-'+role, 'failed', 'Rollback needs operator attention; check SSH and systemd')


class Worker:
    def __init__(self, root=ROOT, live=LIVE, runner_factory=Runner, allow_private=False):
        self.root, self.live = Path(root), Path(live)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700); self.root.chmod(0o700)
        for name in ['plans', 'jobs', 'hosts']:
            (self.root/name).mkdir(exist_ok=True, mode=0o700)
        self.allow_private = allow_private
        from .discovery import Inventory
        self.inventory=Inventory(self.root,self.live);self.remote_inventory=None
        self.connections={}
        self.lock = threading.RLock()
        self.busy = False
        self.task = None
        self.runner_factory = runner_factory
        self.identity = self.root/'identity'
        if not self.identity.exists():
            subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'donino-control', '-f', str(self.identity)], check=True)
        self.identity.chmod(0o600)
        if not self.identity.with_suffix('.pub').exists():
            public = subprocess.check_output(['ssh-keygen','-y','-f',str(self.identity)],text=True)
            self.identity.with_suffix('.pub').write_text(public)
            self.identity.with_suffix('.pub').chmod(0o600)

    def profile(self, identity):
        if not isinstance(identity, str) or not SAFE_ID.fullmatch(identity): raise ValueError('invalid connection ID')
        profiles = read_json(self.root/'profiles.json', [])
        return next((p for p in profiles if p['id'] == identity), None) or self.missing('connection not found')

    @staticmethod
    def missing(message): raise ValueError(message)

    def ssh_args(self, profile):
        return ['ssh', '-F', '/dev/null', '-p', str(profile['port']), '-i', str(self.identity),
                '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                '-o', 'UserKnownHostsFile='+str(self.root/'hosts'/profile['id']),
                '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'ConnectTimeout=10',
                '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=2',
                *(['-o','AddressFamily='+profile['family']] if profile.get('family') else []),'root@'+profile['host']]

    def state(self):
        from .adapters import paqet_overview
        inventory=self.inventory.scan()
        from .paqet import capabilities, status
        with self.lock:
            jobs = [read_json(p) for p in (self.root/'jobs').glob('*/job.json')]
        return {'available': True, 'public_key': self.identity.with_suffix('.pub').read_text().strip(),
                'connections':dict(self.connections),
                'profiles': [{k:p[k] for k in ['id','name','host','port','fingerprint','agent_port','panel_listen','pair_id','management'] if k in p}
                             for p in read_json(self.root/'profiles.json', [])],
                'transports': [{'id': t, 'experimental': t in EXPERIMENTAL} for t in TRANSPORTS],
                'jobs': sorted(jobs, key=lambda j: j['created'], reverse=True)[:20], 'busy': self.busy,
                'iran_address':read_json(self.live,{}).get('public_address'),
                'inventory':inventory,'remote_inventory':self.remote_inventory,'paqet_capabilities':capabilities(),'paqet':paqet_overview(status(self.live.parent),inventory), 'active_spec':self.active_spec()}

    def active_spec(self):
        from .paqet import safe_options
        live=read_json(self.live,{})
        jobs=sorted([read_json(p) for p in (self.root/'jobs').glob('*/job.json')],key=lambda j:j['created'],reverse=True)
        for job in jobs:
            if job.get('status')!='succeeded':continue
            directory=self.root/'plans'/job['plan_id'];meta=read_json(directory/'control.json',{})
            if read_json(directory/'iran/node.json',{}).get('health_key')!=live.get('health_key'):continue
            spec=json.loads(json.dumps(meta.get('spec')))
            if spec and 'paqet_options' in spec:spec['paqet_options']=safe_options(spec['paqet_options'])
            return spec
        return None

    async def paqet_action(self,body):
        from .paqet import UNIT, DIAGNOSTICS, diagnostic
        strict_fields(body,['action'],['action'])
        action=body['action']
        if action not in (*DIAGNOSTICS,'start','stop','restart','udp-test'):raise ValueError('invalid Paqet action')
        if UNIT not in read_json(self.live.parent/'install.json',{}).get('units',[]):raise ValueError('Paqet is not installed')
        with self.lock:
            if self.busy:raise ValueError('installation or action already running')
            self.busy=True
        try:
            if action=='udp-test':
                from .udp_health import probe
                cfg=load_config(self.live);path=next((p for p in cfg['paths'] if p['id']=='paqet'),{})
                if not path.get('udp_health'):raise ValueError('reinstall Paqet with the UDP health channel first')
                try:return {'action':action,'ok':True,'latency_ms':await probe(path['udp_health'],cfg['health_key']), 'meaning':'authenticated native UDP round trip; not an origin application test'}
                except (OSError,asyncio.TimeoutError):return {'action':action,'ok':False,'error':'UDP round trip failed'}
            if action in DIAGNOSTICS:return await asyncio.to_thread(diagnostic,action,self.live.parent)
            result=await asyncio.to_thread(subprocess.run,['systemctl',action,UNIT],capture_output=True,timeout=45)
            if result.returncode:raise ValueError('Paqet service operation failed; inspect its journal')
            return {'action':action,'ok':True}
        finally:
            with self.lock:self.busy=False

    async def imported_action(self,body):
        strict_fields(body,['id','action','enabled','cursor','revision','config','ack_peer_change','profile_id'],['id','action'])
        op=body['action']
        if op=='logs':return await asyncio.to_thread(self.inventory.logs,body['id'],body.get('cursor'))
        if op=='inspect':return await asyncio.to_thread(self.inventory.scan,True)
        if op not in ('manage','start','stop','restart','edit','test'):raise ValueError('invalid detected service action')
        with self.lock:
            if self.busy:raise ValueError('installation or service operation already running')
            self.busy=True
        try:
            if op=='manage':return await asyncio.to_thread(self.inventory.enable,body['id'],body.get('enabled'))
            if op=='edit':return await asyncio.to_thread(self.inventory.edit,body['id'],body.get('revision'),body.get('config'),body.get('ack_peer_change',False))
            if op=='test':
                from .peer import peer_request
                from .import_health import test,key_id
                row=await asyncio.to_thread(self.inventory.select,body['id'])
                if row['engine']!='paqet':
                    return {'tcp_ok':None,'udp_ok':None,'unit':row['unit'],'verification':'process-only','active':row['active'],
                            'reason':'Process and logs are available; this imported vendor installation has no signed Donino probe route. No configuration was changed.'}
                profile=self.profile(body.get('profile_id'));remote=await peer_request(profile,'/inventory',{})
                self.remote_inventory={'time':time.time(),**remote}
                fingerprint=key_id(row.get('config',{}))
                if row.get('role')!='client' or not fingerprint:raise ValueError('a client Paqet configuration with a matching key is required')
                port=endpoint(row['config']['server']['addr'])[1]
                match=next((r for r in remote['services'] if r.get('engine')=='paqet' and r.get('role')=='server' and r.get('key_id')==fingerprint and str(r.get('config',{}).get('listen',{}).get('addr','')).endswith(':'+str(port))),None)
                if not match:raise ValueError('no paired foreign Paqet server with the same key was detected')
                targets=list(dict.fromkeys(r['target'] for r in row['config'].get('forward',[]) if r.get('protocol','tcp')=='tcp' and loopback(r['target'])))[:32]
                material=await peer_request(profile,'/external-health',{'id':match['id'],'targets':targets})
                result=await asyncio.to_thread(test,row['config'],material)
                result.setdefault('origin_targets',material.get('targets',[]))
                result['config_match']=row['config'].get('transport',{}).get('kcp',{}).get('block','aes')==match.get('config',{}).get('transport',{}).get('kcp',{}).get('block','aes')
                observation={**result,'revision':row.get('revision'),'time':time.time(),'key_id':key_id(row['config']),'server_id':match['id']}
                self.inventory.record_health(row['id'],observation)
                await peer_request(profile,'/external-observation',observation)
                return {**observation,'unit':row['unit']}
            return await asyncio.to_thread(self.inventory.control,body['id'],op)
        finally:
            with self.lock:self.busy=False

    def pair(self, body):
        from .peer import split_code,peer_request
        strict_fields(body,['name','host','agent_port','code'],['name','host','agent_port','code'])
        if self.busy:raise ValueError('installation already running')
        host=public_address(body['host']);port=integer(body['agent_port'],1024,65535,'pairing port')
        addresses=socket.getaddrinfo(host,port,type=socket.SOCK_STREAM)
        if not addresses or (not self.allow_private and any(not ipaddress.ip_address(a[4][0]).is_global for a in addresses)):
            raise ValueError('foreign pairing address must resolve to public IPs')
        if not isinstance(body['name'],str) or not 1<=len(body['name'])<=64:raise ValueError('invalid connection name')
        pin,token=split_code(body['code'])
        peer={'host':host,'agent_port':port,'agent_fingerprint':pin}
        result=asyncio.run(peer_request(peer,'/exchange',{'token':token,'public_key':self.identity.with_suffix('.pub').read_text().strip(),'name':body['name'],'management':'https-v1'}))
        try:
            strict_fields(result,['pair_id','agent_token','management','panel_listen'],['pair_id','agent_token','management','panel_listen'])
            if result['management']!='https-v1':raise ValueError('Upgrade the foreign agent to pinned HTTPS management')
            endpoint(result['panel_listen'])
            if not isinstance(result['pair_id'],str) or not SAFE_ID.fullmatch(result['pair_id']) or not isinstance(result['agent_token'],str) or not re.fullmatch('[A-Za-z0-9_-]{43}',result['agent_token']):raise ValueError('invalid pairing response')
            profile={'id':secrets.token_hex(16),'name':body['name'],'host':host,'management':'https-v1',
                     'agent_port':port,'agent_fingerprint':pin,'agent_token':result['agent_token'],
                     'pair_id':result['pair_id'],'panel_listen':result['panel_listen']}
            self.check_profile(profile)
            with self.lock:
                if self.busy:raise ValueError('installation already running')
                profiles=read_json(self.root/'profiles.json',[])
                if len(profiles)>=20:raise ValueError('maximum 20 connections')
                profiles.append(profile)
                atomic_json(self.root/'profiles.json',profiles)
            return {k:profile[k] for k in ['id','name','host','management']}
        except Exception:
            try:asyncio.run(peer_request(peer,'/revoke-self',{},token=result['agent_token']))
            except Exception:pass
            raise

    def check_profile(self, profile):
        from .peer import peer_request
        from .management import PROTOCOL,runtime_digest
        challenge=secrets.token_hex(32)
        result=asyncio.run(peer_request(profile,'/connection',{'challenge':challenge}))
        if result.get('management')!=PROTOCOL or not isinstance(result.get('proof'),str) or not secrets.compare_digest(result['proof'],hashlib.sha256(challenge.encode()).hexdigest()):
            raise ValueError('Foreign management write/read proof failed')
        evidence={'ok':True,'time':time.time(),'management':PROTOCOL,'ready':result.get('ready') is True,
                  'runtime_match':result.get('runtime_digest')==runtime_digest(),'version':result.get('version')}
        self.connections[profile['id']]=evidence
        return evidence

    def check_connection(self, body):
        strict_fields(body,['profile_id'],['profile_id'])
        profile=self.profile(body['profile_id'])
        if not profile.get('agent_token'):raise ValueError('Manual SSH profile has no management pairing; pair using the foreign panel code')
        try:return self.check_profile(profile)
        except Exception:
            self.connections[profile['id']]={'ok':False,'time':time.time(),'management':'https-v1'}
            raise

    async def remote_action(self, body):
        from .peer import peer_request
        strict_fields(body,['profile_id','kind','body'],['profile_id','kind','body'])
        if body['kind'] not in ('service','imported','inventory'):raise ValueError('invalid remote action kind')
        profile=self.profile(body['profile_id'])
        if not profile.get('agent_token'):raise ValueError('Pair the management agent first')
        if body['kind']!='inventory' and self.busy:raise ValueError('installation already running')
        route={'service':'/node-action','imported':'/node-imported-action','inventory':'/inventory'}[body['kind']]
        return await peer_request(profile,route,body['body'])

    async def observe(self):
        """Only signed, actual carrier probes are sent to the foreign panel."""
        from .peer import peer_request,digest
        from aiohttp import ClientError
        from .cli import doctor
        cfg=load_config(self.live)
        profiles=[p for p in read_json(self.root/'profiles.json',[]) if p.get('agent_token')]
        if not profiles:return
        for profile in reversed(profiles):
            try:
                from .peer import peer_request
                self.remote_inventory={'time':time.time(),**await peer_request(profile,'/inventory',{})};break
            except (OSError,ValueError,ClientError,asyncio.TimeoutError):continue
        if not cfg.get('paths'):return
        rows=await doctor(cfg)
        for profile in reversed(profiles):
            try:
                await peer_request(profile,'/telemetry',{'config_hash':digest(cfg['health_key']),'probes':rows})
                break  # The matching installation is identified by its health key.
            except (OSError,ValueError,ClientError,asyncio.TimeoutError):continue

    def add_profile(self, body):
        strict_fields(body, ['name', 'host', 'port', 'fingerprint','family','key_type'], ['name', 'host', 'port', 'fingerprint'])
        if body.get('family') is not None and body['family'] not in ('inet','inet6'):raise ValueError('invalid SSH address family')
        if not isinstance(body['name'], str) or not 1 <= len(body['name']) <= 64: raise ValueError('invalid connection name')
        host = public_address(body['host']); port = integer(body['port'], 1, 65535, 'SSH port')
        # SSH targets must resolve exclusively to public IPs, not localhost,
        # metadata endpoints or private services on the controller.
        addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        if not addresses or (not self.allow_private and any(not ipaddress.ip_address(a[4][0]).is_global for a in addresses)):
            raise ValueError('foreign SSH address must resolve to public IPs')
        line = scan_pinned_key(host,port,body['fingerprint'],body.get('key_type'))
        profile = {'id': secrets.token_hex(16), 'name': body['name'], 'host': host, 'port': port, 'fingerprint': body['fingerprint']}
        if body.get('family'):profile['family']=body['family']
        path = self.root/'hosts'/profile['id']; path.write_text(line); path.chmod(0o600)
        # Only save a usable connection; the public key must already be authorized.
        runner = self.runner_factory(self.root/'connection.log')
        try:
            runner.run(self.ssh_args(profile)+['test "$(id -u)" -eq 0 && command -v python3 && test -d /run/systemd/system'], timeout=25)
            with self.lock:
                profiles = read_json(self.root/'profiles.json', [])
                if len(profiles) >= 20: raise ValueError('maximum 20 connections')
                profiles.append(profile); atomic_json(self.root/'profiles.json', profiles)
        except Exception:
            path.unlink(missing_ok=True); raise
        return profile

    def validate_spec(self, body):
        fields = ['profile_id', 'iran', 'foreign', 'services', 'transports', 'experimental', 'base_port', 'carrier_base', 'health_port', 'paqet_port', 'browser_port', 'open_ufw','paqet_options','paqet_keep_secrets','continuum_options']
        strict_fields(body, fields, ['profile_id', 'iran', 'services', 'transports'])
        profile = self.profile(body['profile_id'])
        if not isinstance(body['services'], list) or not 0 <= len(body['services']) <= 40: raise ValueError('use up to 40 TCP/UDP services')
        for service in body['services']:
            strict_fields(service, ['id', 'listen', 'target', 'protocol'], ['id', 'listen', 'target'])
            if not all(isinstance(service[k],str) and len(service[k])<=300 for k in ['id','listen','target']): raise ValueError('invalid service field')
        if not isinstance(body['transports'], list) or not all(isinstance(t, str) for t in body['transports']): raise ValueError('invalid transports')
        if not isinstance(body.get('open_ufw', False), bool): raise ValueError('open_ufw must be boolean')
        if not isinstance(body.get('experimental', False), bool): raise ValueError('experimental must be boolean')
        spec = dict(body); spec['iran'] = public_address(body['iran']); spec['foreign'] = public_address(body.get('foreign') or profile['host'])
        for field, default in [('base_port', 30000), ('carrier_base', 24443), ('health_port', 19090), ('paqet_port', 33434)]:
            spec[field] = integer(spec.get(field, default), 1024, 65535, field)
        if spec.get('browser_port') is not None: integer(spec['browser_port'], 1, 65535, 'browser port')
        if type(spec.get('paqet_keep_secrets',False)) is not bool:raise ValueError('Paqet keep secrets must be boolean')
        if 'continuum_options' in spec:
            from .continuum import options
            if 'donino-continuum' not in spec['transports']:raise ValueError('Continuum settings require Continuum')
            spec['continuum_options']=options(spec['continuum_options'])
        if 'paqet_options' in spec:
            from .paqet import options
            if 'paqet' not in spec['transports']:raise ValueError('Paqet settings require Paqet')
            raw=spec['paqet_options']
            if spec.get('paqet_keep_secrets'):
                raw=json.loads(json.dumps(raw))
                if not isinstance(raw,dict):raise ValueError('invalid Paqet settings')
                old=read_json(self.live.parent/'transports/paqet.yaml',{})
                if not raw.get('key') and old.get('transport',{}).get('kcp',{}).get('key'):raw['key']=old['transport']['kcp']['key']
                credentials={(r['listen'],r.get('username','')):r.get('password','') for r in old.get('socks5',[])}
                if not isinstance(raw.get('socks5',[]),list):raise ValueError('invalid Paqet SOCKS5 settings')
                for row in raw.get('socks5',[]):
                    if isinstance(row,dict) and row.get('username') and not row.get('password'):row['password']=credentials.get((row.get('listen'),row['username']),'')
            spec['paqet_options']=options(raw)
        return spec

    def preview(self, body):
        with self.lock:
            if self.busy: raise ValueError('installation already running')
            spec = self.validate_spec(body)
            # Retain 20 recent terminal jobs plus the most recent successful
            # plan (its controller CA is still needed for that installation).
            records = [(p,read_json(p)) for p in (self.root/'jobs').glob('*/job.json')]
            records.sort(key=lambda item:item[1]['created'],reverse=True)
            terminal = [item for item in records if item[1]['status']!='running']
            keep = {item[1]['id'] for item in terminal[:20]}
            successful = next((item for item in terminal if item[1]['status']=='succeeded'),None)
            if successful:keep.add(successful[1]['id'])
            for path,job in terminal:
                if job['id'] not in keep:
                    shutil.rmtree(self.root/'plans'/job['plan_id'],ignore_errors=True)
                    shutil.rmtree(path.parent,ignore_errors=True)
            # Bound private plan storage. Unused previews expire after one hour.
            for p in (self.root/'plans').iterdir():
                meta = read_json(p/'control.json', {})
                if not meta.get('used') and time.time()-meta.get('created', p.stat().st_mtime)>3600: shutil.rmtree(p)
            if len(list((self.root/'plans').iterdir())) >= 50: raise ValueError('private plan storage limit reached')
            identity = secrets.token_hex(16); directory = self.root/'plans'/identity
            live = load_config(self.live)
            # Preserve existing authentication/listener; nobody enters a new admin
            # password into this workflow and upgrades do not silently rebind it.
            try:
                summary = make_plan(directory, spec['iran'], spec['foreign'], spec['services'], spec['transports'],
                                    secrets.token_urlsafe(24), spec.get('experimental', False), spec['base_port'],
                                    spec['carrier_base'], spec['health_port'], spec['paqet_port'], spec.get('browser_port'),
                                    panel_port=endpoint(live['panel']['listen'])[1],paqet_options=spec.get('paqet_options'),continuum_options=spec.get('continuum_options'))
                node = read_json(directory/'iran/node.json'); node['panel'] = live['panel']; node['state_db'] = live['state_db']
                node['public_address']=spec['iran']
                atomic_json(directory/'iran/node.json', node)
                shutil.copyfile(live['panel']['credentials_file'], directory/'iran/admin.json')
                shutil.copyfile(live['panel']['api_token_file'], directory/'iran/api-token')
                # Keep panel TLS files within the new node if the old release owns them.
                for field in ['tls_cert', 'tls_key']:
                    if live['panel'].get(field):
                        target = directory/'iran'/'panel-tls'/('cert.pem' if field=='tls_cert' else 'key.pem')
                        target.parent.mkdir(exist_ok=True, mode=0o700); shutil.copyfile(live['panel'][field], target); target.chmod(0o600)
                        node['panel'][field] = '/etc/donino-link/current/panel-tls/'+target.name
                atomic_json(directory/'iran/node.json', node); load_config(directory/'iran/node.json')
                meta = {'profile_id': spec['profile_id'], 'created': time.time(), 'used': False, 'live_hash': hashlib.sha256(self.live.read_bytes()).hexdigest(),'spec':spec}
                for role in ['iran','foreign']:
                    install = read_json(directory/role/'install.json'); install['open_ufw'] = spec.get('open_ufw', False); atomic_json(directory/role/'install.json', install)
                summary['host_firewall'] = 'active-ufw-only' if spec.get('open_ufw') else 'manual'
                if self.profile(spec['profile_id']).get('panel_listen'):
                    profile=self.profile(spec['profile_id']);foreign_ports=[endpoint(profile['panel_listen'])[1],profile['agent_port']]
                    staged=read_json(directory/'foreign/install.json')
                    occupied={item['port'] for item in staged['listeners']}|{endpoint(t)[1] for t in read_json(directory/'foreign/node.json')['targets'].values()}
                    if set(foreign_ports)&occupied:raise ValueError('foreign panel or pairing port conflicts with a tunnel listener or origin')
                    summary['firewall']['foreign']['tcp']=sorted(set(summary['firewall']['foreign']['tcp']+foreign_ports))
                summary['firewall']['iran']['tcp'] = sorted(set(summary['firewall']['iran']['tcp']+[endpoint(live['panel']['listen'])[1]]))
                atomic_json(directory/'plan.json',summary)
                atomic_json(directory/'control.json', meta)
                return {'id': identity, 'summary': summary, 'expires_at': meta['created']+3600,
                        'notice': 'Replaces the complete managed tunnel set on both nodes. Existing connections may be interrupted. The panel restarts; its password and address stay the same.'}
            except Exception:
                shutil.rmtree(directory, ignore_errors=True); raise

    def save_job(self, job):
        with self.lock: atomic_json(self.root/'jobs'/job['id']/'job.json', job)

    def event(self, job, stage, status, message):
        job['stage'] = stage; job['updated'] = time.time()
        job['events'].append({'time': job['updated'], 'stage': stage, 'status': status, 'message': message})
        self.save_job(job)

    async def start(self, body):
        strict_fields(body, ['plan_id', 'confirm_replace'], ['plan_id', 'confirm_replace'])
        if body['confirm_replace'] is not True: raise ValueError('review and acknowledge replacement first')
        identity = body['plan_id']
        if not isinstance(identity, str) or not SAFE_ID.fullmatch(identity): raise ValueError('invalid plan ID')
        with self.lock:
            if self.busy: raise ValueError('installation already running')
            meta = read_json(self.root/'plans'/identity/'control.json')
            if not meta or meta['used'] or time.time()-meta['created']>3600: raise ValueError('plan expired or already used; preview again')
            if meta['live_hash'] != hashlib.sha256(self.live.read_bytes()).hexdigest(): raise ValueError('live configuration changed; preview again')
            self.profile(meta['profile_id'])
            jid = secrets.token_hex(16); (self.root/'jobs'/jid).mkdir(mode=0o700)
            job = {'id': jid, 'plan_id': identity, 'status': 'running', 'stage': 'queued', 'created': time.time(), 'updated': time.time(),
                   'events': [], 'prepared': [], 'activated': [], 'activating': None, 'probes': []}
            self.save_job(job); meta['used'] = True; atomic_json(self.root/'plans'/identity/'control.json', meta)
            self.busy = True
        self.task = asyncio.create_task(self.run_job(job))
        return job

    async def run_job(self, job, recovery=False):
        try:
            runner = self.runner_factory(self.root/'jobs'/job['id']/'private.log')
            coordinator = Coordinator(self, runner)
            if recovery:
                meta = read_json(self.root/'plans'/job['plan_id']/'control.json')
                meta['used'] = True; atomic_json(self.root/'plans'/job['plan_id']/'control.json',meta)
                await asyncio.to_thread(coordinator.rollback, job, self.profile(meta['profile_id']))
                if job['status'] != 'rollback_failed': job['status'] = 'interrupted'
                self.event(job, 'recovery', 'failed', 'Worker restarted during installation; active changes were rolled back. Preview a new plan to retry.')
            else:
                await asyncio.to_thread(coordinator.execute, job)
        except Exception as error:
            job['status'] = 'rollback_failed' if recovery else 'failed'
            job['error'] = 'Controller operation failed: '+type(error).__name__
            self.event(job, 'failure', 'failed', job['error'])
        finally:
            if recovery:
                try:
                    from .peer import peer_request
                    meta=read_json(self.root/'plans'/job['plan_id']/'control.json')
                    profile=self.profile(meta['profile_id'])
                    if profile.get('agent_token'):await peer_request(profile,'/release',{'job_id':job['id']})
                except Exception:
                    self.event(job,'lease-release','failed','Foreign lease could not be released; it expires automatically.')
            self.busy = False

    async def recover(self):
        jobs = [read_json(p) for p in (self.root/'jobs').glob('*/job.json')]
        for job in jobs:
            if job['status'] == 'running':
                self.busy = True
                await self.run_job(job, recovery=True)


def application(worker):
    @web.middleware
    async def errors(request, handler):
        try: return await handler(request)
        except ValueError as error: return web.json_response({'error': str(error)}, status=400)
        except (CommandFailure, subprocess.TimeoutExpired,ClientError):
            return web.json_response({'error': 'SSH or prerequisite check failed. Verify authorization, fingerprint and connectivity; private worker log contains details.'}, status=502)
        except OSError:
            return web.json_response({'error': 'Controller resource or network unavailable'}, status=503)
    app = web.Application(client_max_size=65536, middlewares=[errors])
    async def state(request): return web.json_response(await asyncio.to_thread(worker.state))
    async def profiles(request): return web.json_response(await asyncio.to_thread(worker.add_profile, await request.json()), status=201)
    async def pair(request): return web.json_response(await asyncio.to_thread(worker.pair,await request.json()),status=201)
    async def preview(request): return web.json_response(await asyncio.to_thread(worker.preview, await request.json()), status=201)
    async def start(request): return web.json_response(await worker.start(await request.json()), status=202)
    async def paqet_action(request):return web.json_response(await worker.paqet_action(await request.json()))
    async def imported_action(request):return web.json_response(await worker.imported_action(await request.json()))
    async def connection(request):return web.json_response(await asyncio.to_thread(worker.check_connection,await request.json()))
    async def remote_action(request):return web.json_response(await worker.remote_action(await request.json()))
    app.add_routes([web.post('/connection',connection),web.post('/remote-action',remote_action),web.post('/imported-action',imported_action),web.get('/state', state), web.post('/profiles', profiles), web.post('/pair',pair),web.post('/preview', preview), web.post('/start', start),web.post('/paqet-action',paqet_action)])
    async def cleanup(app):
        if worker.task: await worker.task
    from .vpn_backend import Backend
    backend = Backend()
    async def vpn_backend(request):
        result = await asyncio.to_thread(backend.status) if request.method == 'GET' else await asyncio.to_thread(backend.install, await request.json())
        return web.json_response(result)
    app.add_routes([web.get('/vpn-backend', vpn_backend), web.post('/vpn-backend', vpn_backend)])
    async def vpn_remote(request):
        from .vpn_bridge import remote
        return web.json_response(await remote(worker,await request.json(),api=request.path=='/vpn-backend-api'))
    app.add_routes([web.post('/vpn-backend-remote',vpn_remote),web.post('/vpn-backend-api',vpn_remote)])
    app.on_cleanup.append(cleanup)
    return app


async def serve_control():
    if os.geteuid() != 0: raise ValueError('control service must run as root')
    import fcntl
    import grp
    ROOT.mkdir(mode=0o700, exist_ok=True)
    lock = (ROOT/'worker.lock').open('w')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    settings = read_json('/etc/donino-control.json', {})
    worker = Worker(allow_private=settings.get('allow_private_peers') is True)
    # Recovery runs before accepting new mutations.
    await asyncio.to_thread(worker.inventory.recover)
    await worker.recover()
    runner = web.AppRunner(application(worker), access_log=None); await runner.setup()
    SOCKET.parent.mkdir(mode=0o750, exist_ok=True)
    os.chown(SOCKET.parent, 0, grp.getgrnam('donino-link').gr_gid); SOCKET.parent.chmod(0o750)
    SOCKET.unlink(missing_ok=True)
    await web.UnixSite(runner, str(SOCKET)).start()
    os.chown(SOCKET, 0, grp.getgrnam('donino-link').gr_gid); SOCKET.chmod(0o660)
    stop = asyncio.Event()
    import signal
    for sig in [signal.SIGTERM, signal.SIGINT]: asyncio.get_running_loop().add_signal_handler(sig, stop.set)
    async def observations():
        from aiohttp import ClientError
        while True:
            try:await worker.observe()
            except (OSError,ValueError,KeyError,ClientError,asyncio.TimeoutError):pass
            await asyncio.sleep(10)
    observer=asyncio.create_task(observations())
    try: await stop.wait()
    finally:
        observer.cancel()
        await asyncio.gather(observer,return_exceptions=True)
        await runner.cleanup(); SOCKET.unlink(missing_ok=True); lock.close()


def enable_control(allow_private=False):
    if os.geteuid() != 0: raise ValueError('run control-enable as root on the Iran server')
    if load_config(LIVE)['role'] != 'iran': raise ValueError('control service belongs on the Iran server')
    if allow_private:
        atomic_json('/etc/donino-control.json', {'allow_private_peers':True})
    # Separate from the tunnel release's unit manifest: a panel upgrade never
    # stops the job supervising that upgrade.
    unit = '''[Unit]
Description=Donino two-node installation controller
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=root
ExecStart=/opt/donino-link/current/venv/bin/donino-link control-run
Restart=on-failure
RestartSec=5
TimeoutStopSec=2100
UMask=0077
RuntimeDirectory=donino-control
RuntimeDirectoryMode=0750
# Existing vendor configurations may live under /root or /home.
# Only the private root agent accesses them; the web process stays sandboxed.
ProtectHome=false
PrivateTmp=true
[Install]
WantedBy=multi-user.target
'''
    Path('/etc/systemd/system/donino-control.service').write_text(unit)
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    subprocess.run(['systemctl', 'enable', '--now', 'donino-control.service'], check=True)
    print('Installation controller enabled. Refresh the panel and open Automatic setup.')
