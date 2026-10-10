"""Foreign root agent: expiring pairing, scoped SSH keys and fixed node actions.

Admin panels use HTTP by explicit operator choice. The pairing/telemetry channel
is separately TLS encrypted and pins the complete certificate before HTTP data.
No arbitrary command, file path, key algorithm or download URL is accepted.
"""
import asyncio
import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import signal
import ssl
import subprocess
import threading
import time
from collections import OrderedDict
from pathlib import Path
from aiohttp import web, ClientSession, ClientTimeout, Fingerprint
from .config import atomic_json, endpoint, load_config
from .provision import strict_fields, integer, read_json, SAFE_ID

ROOT = Path('/var/lib/donino-foreign')
SOCKET = Path('/run/donino-foreign/agent.sock')
SETTINGS = Path('/etc/donino-foreign-agent.json')
LIVE = Path('/etc/donino-link/current/node.json')
SSH_DROPIN = Path('/etc/ssh/sshd_config.d/00-donino-pair.conf')
OBSERVATIONS = Path('/var/lib/donino-link/peer-observations.json')


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def key_fields(value):
    if not isinstance(value, str) or len(value) > 200:
        raise ValueError('invalid public key')
    parts = value.split()
    if len(parts) not in (2, 3) or parts[0] != 'ssh-ed25519':
        raise ValueError('only an Ed25519 public key is accepted')
    try:
        raw = base64.b64decode(parts[1], validate=True)
    except ValueError:
        raise ValueError('invalid public key encoding') from None
    if len(raw) != 51 or raw[:19] != b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20':
        raise ValueError('invalid Ed25519 key structure')
    return 'ssh-ed25519 '+parts[1]


def split_code(code):
    if not isinstance(code, str) or not re.fullmatch(r'donino1\.[0-9a-f]{64}\.[A-Za-z0-9_-]{43}', code):
        raise ValueError('invalid Donino pairing code')
    _, fingerprint, token = code.split('.')
    return fingerprint, token


async def peer_request(profile, path, body=None, token=None):
    if path not in ('/exchange', '/telemetry', '/lease', '/release', '/revoke-self'):
        raise ValueError('unsupported peer operation')
    host = profile['host']
    if ':' in host: host = '['+host+']'
    port = integer(profile['agent_port'], 1, 65535, 'agent port')
    pin = profile['agent_fingerprint']
    if not isinstance(pin, str) or not re.fullmatch('[0-9a-f]{64}', pin):
        raise ValueError('invalid peer certificate pin')
    headers = {'Authorization': 'Bearer '+(token or profile.get('agent_token',''))}
    async with ClientSession(timeout=ClientTimeout(total=30), trust_env=False) as session:
        async with session.post(f'https://{host}:{port}'+path, json=body, headers=headers,
                                ssl=Fingerprint(bytes.fromhex(pin)), allow_redirects=False) as response:
            raw = await response.content.read(32769)
            if len(raw) > 32768: raise ValueError('peer response too large')
            if response.status==401:raise ValueError('foreign management permission was revoked; generate a new pairing code')
            try:result=json.loads(raw)
            except ValueError:raise ValueError('foreign agent endpoint did not accept the request') from None
            if response.status >= 400: raise ValueError(result.get('error','peer rejected operation'))
            if response.status != 200: raise ValueError('peer redirected operation')
            return result


def ssh_rules(root, pairs):
    """Rebuild only our dedicated key file/drop-in, preserving user key files."""
    active = [p for p in pairs if not p.get('revoked')]
    lines = [f'from="{p["source"]}",restrict {key_fields(p["public_key"])} donino:{p["id"]}' for p in active]
    keys = root/'authorized_keys'
    previous_keys=keys.read_text() if keys.exists() else ''
    def replace(path, text, mode):
        temporary=path.with_name(path.name+'.new')
        with temporary.open('w') as stream:
            os.chmod(temporary,mode);stream.write(text);stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,path)
    replace(keys,'\n'.join(lines)+'\n',0o600)
    previous = SSH_DROPIN.read_text() if SSH_DROPIN.exists() else None
    text = '# Owned by Donino: only paired source addresses; user key files are preserved.\n'
    if active:
        addresses = ','.join(sorted({str(ipaddress.ip_address(p['source'])) for p in active}))
        text += f'Match User root Address {addresses}\n    PermitRootLogin prohibit-password\n    PubkeyAuthentication yes\n    AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2 {keys}\nMatch all\n'
    SSH_DROPIN.parent.mkdir(parents=True, exist_ok=True)
    replace(SSH_DROPIN,text,0o644)
    try:
        subprocess.run(['/usr/sbin/sshd','-t'], check=True, capture_output=True, timeout=10)
        subprocess.run(['systemctl','reload','ssh.service'], check=True, capture_output=True, timeout=15)
    except Exception:
        # Do not restore a revoked key when sshd validation/reload fails. Retain
        # only keys present in BOTH the preceding and requested authorization.
        retained=set(lines)
        replace(keys,'\n'.join(line for line in previous_keys.splitlines() if line in retained)+'\n',0o600)
        if previous is None: SSH_DROPIN.unlink(missing_ok=True)
        else: replace(SSH_DROPIN,previous,0o644)
        raise


class ForeignAgent:
    def __init__(self, root=ROOT, live=LIVE, settings=None, ssh_writer=ssh_rules):
        self.root, self.live = Path(root), Path(live)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700); self.root.chmod(0o700)
        self.settings = settings or read_json(SETTINGS, {})
        self.ssh_writer = ssh_writer
        self.lock = threading.RLock()
        self.attempts = OrderedDict()
        self.tasks = set()
        from .discovery import Inventory
        self.inventory=Inventory(self.root,self.live);self.probe_udp=None;self.probe_udp_lock=asyncio.Lock()
        self.action_busy = False
        self.fingerprint = self.settings['fingerprint']

    def pairs(self): return read_json(self.root/'pairs.json', [])

    def publish_telemetry(self, data):
        atomic_json(self.root/'telemetry.json',data)
        # Readable sanitized observations for the unprivileged foreign panel.
        import grp
        atomic_json(OBSERVATIONS,data)
        os.chown(OBSERVATIONS,0,grp.getgrnam('donino-link').gr_gid)
        os.chmod(OBSERVATIONS,0o640)

    def lease(self):
        lease = read_json(self.root/'lease.json', {})
        return lease if lease.get('expires',0) > time.time() else None

    def pairing_code(self):
        with self.lock:
            if self.lease() or self.action_busy: raise ValueError('node is busy')
            token = secrets.token_urlsafe(32)
            atomic_json(self.root/'pending.json', {'digest':digest(token), 'expires':time.time()+600})
            return {'code':'donino1.'+self.fingerprint+'.'+token, 'expires_at':time.time()+600,
                    'agent_port':self.settings['port'], 'single_use':True}

    def exchange(self, body, source):
        strict_fields(body, ['token','public_key','name'], ['token','public_key','name'])
        key = key_fields(body['public_key']); source = str(ipaddress.ip_address(source))
        if not isinstance(body['name'], str) or not 1 <= len(body['name']) <= 64: raise ValueError('invalid peer name')
        if not isinstance(body['token'], str) or len(body['token']) > 100: raise ValueError('invalid pairing token')
        with self.lock:
            if self.lease() or self.action_busy: raise ValueError('node is busy')
            now = time.time(); count, until = self.attempts.get(source,(0,now+60))
            if until < now: count, until = 0, now+60
            self.attempts[source] = (count+1,until); self.attempts.move_to_end(source)
            while len(self.attempts)>1024: self.attempts.popitem(last=False)
            if count >= 5: raise ValueError('pairing rate limit; wait one minute')
            pending = read_json(self.root/'pending.json', {})
            if pending.get('expires',0) < now or not hmac.compare_digest(pending.get('digest',''), digest(body['token'])):
                raise ValueError('pairing code expired, used or incorrect')
            pairs = self.pairs()
            if sum(not p.get('revoked') for p in pairs) >= 20: raise ValueError('maximum 20 peers')
            token = secrets.token_urlsafe(32)
            record = {'id':secrets.token_hex(16), 'name':body['name'], 'source':source, 'public_key':key,
                      'created':now, 'token_digest':digest(token), 'revoked':False}
            # Consume before side effects; a lost response needs a fresh code.
            (self.root/'pending.json').unlink(missing_ok=True)
            pairs=[p for p in pairs if not p.get('revoked')]+[p for p in pairs if p.get('revoked')][-20:]
            pairs.append(record); atomic_json(self.root/'pairs.json',pairs)
            try: self.ssh_writer(self.root,pairs)
            except Exception:
                record['revoked']=True; atomic_json(self.root/'pairs.json',pairs)
                raise
            host_key = subprocess.check_output(['ssh-keygen','-lf','/etc/ssh/ssh_host_ed25519_key.pub'],text=True,timeout=5).split()[1]
            return {'pair_id':record['id'], 'agent_token':token, 'ssh_fingerprint':host_key,
                    'ssh_family':'inet' if ipaddress.ip_address(source).version==4 else 'inet6',
                    'ssh_port':self.settings['ssh_port'], 'panel_listen':load_config(self.live)['panel']['listen']}

    def authenticate(self, header, source):
        token = header.removeprefix('Bearer ') if header.startswith('Bearer ') else ''
        if len(token)>100: raise web.HTTPUnauthorized()
        actual = digest(token)
        for pair in self.pairs():
            if not pair.get('revoked') and pair['source']==str(ipaddress.ip_address(source)) and hmac.compare_digest(actual,pair['token_digest']):
                return pair
        raise web.HTTPUnauthorized()

    def revoke(self, identity):
        if not isinstance(identity,str) or not SAFE_ID.fullmatch(identity): raise ValueError('invalid peer ID')
        with self.lock:
            if self.lease() or self.action_busy: raise ValueError('installation or service action is running')
            pairs = self.pairs(); pair = next((p for p in pairs if p['id']==identity),None)
            if pair is None: raise ValueError('peer not found')
            pair['revoked']=True; atomic_json(self.root/'pairs.json',pairs)
            if read_json(self.root/'telemetry.json',{}).get('peer_id')==identity:
                self.publish_telemetry({})
            self.ssh_writer(self.root,pairs)
            return {'revoked':True,'tunnels_stopped':False}

    def telemetry(self, pair, body):
        strict_fields(body, ['config_hash','probes','gateway'], ['config_hash','probes'])
        config = load_config(self.live)
        if body['config_hash'] != digest(config['health_key']): raise ValueError('telemetry belongs to another installation')
        probes = body['probes']
        install = read_json(self.live.parent/'install.json', {})
        from .plan import TRANSPORTS
        names = {u.removeprefix('donino-link-').removesuffix('.service') for u in install.get('units',[])} & set(TRANSPORTS)
        if not isinstance(probes,list) or len(probes)>len(names): raise ValueError('invalid probes')
        clean=[];seen=set()
        for row in probes:
            strict_fields(row,['path','ok','latency_ms','services','error','udp_ok','udp_latency_ms'],['path','ok'])
            if not isinstance(row['path'],str) or row['path'] not in names or row['path'] in seen or not isinstance(row['ok'],bool): raise ValueError('unknown probe path or duplicate')
            seen.add(row['path'])
            latency = row.get('latency_ms')
            if latency is not None and (isinstance(latency,bool) or not isinstance(latency,(int,float)) or not 0<=latency<=60000): raise ValueError('invalid latency')
            services = row.get('services',{})
            if not isinstance(services,dict) or set(services)-set(config.get('targets',{})) or not all(isinstance(v,bool) for v in services.values()): raise ValueError('invalid service observations')
            clean.append({'path':row['path'],'ok':row['ok'],'latency_ms':latency,'services':services})
            if ('udp_ok' in row or 'udp_latency_ms' in row) and (row['path']!='paqet' or 'udp_ok' not in row):raise ValueError('UDP observations belong to Paqet')
            if row['path']=='paqet' and 'udp_ok' in row:
                if type(row['udp_ok']) is not bool:raise ValueError('invalid UDP observation')
                udp_ms=row.get('udp_latency_ms')
                if udp_ms is not None and (type(udp_ms) not in (int,float) or not 0<=udp_ms<=60000):raise ValueError('invalid UDP latency')
                clean[-1].update(udp_ok=row['udp_ok'],udp_latency_ms=udp_ms)
        data={'time':time.time(),'peer_id':pair['id'],'peer_name':pair['name'],'source':pair['source'],'probes':clean,'config_hash':body['config_hash']}
        # Authentication precedes this worker thread. Recheck while holding the
        # revocation lock so an already authenticated request cannot republish
        # fresh health after its peer has been revoked.
        with self.lock:
            if not any(p['id']==pair['id'] and not p.get('revoked') for p in self.pairs()):
                raise web.HTTPUnauthorized()
            self.publish_telemetry(data)
        return {'accepted':True}

    def reserve(self, pair, body):
        strict_fields(body,['job_id'],['job_id'])
        if not isinstance(body['job_id'],str) or not SAFE_ID.fullmatch(body['job_id']): raise ValueError('invalid job ID')
        with self.lock:
            lease=self.lease()
            if self.action_busy or (lease and (lease['peer_id']!=pair['id'] or lease['job_id']!=body['job_id'])): raise ValueError('foreign node is busy')
            atomic_json(self.root/'lease.json',{'peer_id':pair['id'],'job_id':body['job_id'],'expires':time.time()+3600})
            return {'reserved':True}

    def release(self, pair, body):
        strict_fields(body,['job_id'],['job_id'])
        with self.lock:
            lease=self.lease()
            if lease and lease['peer_id']==pair['id'] and lease['job_id']==body['job_id']:(self.root/'lease.json').unlink(missing_ok=True)
        return {'released':True}

    def state(self):
        from .paqet import status
        pairs=[{k:p[k] for k in ['id','name','source','created','revoked']} for p in self.pairs()]
        telemetry=read_json(self.root/'telemetry.json',None)
        if telemetry and not any(p['id']==telemetry.get('peer_id') and not p['revoked'] for p in pairs):telemetry=None
        for identity,observation in list(self.inventory.health.items()):
            if observation.get('peer_id') and not any(p['id']==observation['peer_id'] and not p['revoked'] for p in pairs):self.inventory.health.pop(identity,None)
        return {'available':True,'agent_port':self.settings['port'],'paired':pairs,'lease':self.lease(),
                'action_busy':self.action_busy,'actions':read_json(self.root/'actions.json',[]),
                'pending_expires':read_json(self.root/'pending.json',{}).get('expires'),
                'telemetry':telemetry,'inventory':self.inventory.scan(),'paqet':status(self.live.parent)}

    async def imported_action(self,body):
        strict_fields(body,['id','action','enabled','cursor','revision','config','ack_peer_change'],['id','action'])
        op=body['action']
        if op=='logs':return await asyncio.to_thread(self.inventory.logs,body['id'],body.get('cursor'))
        if op=='inspect':return await asyncio.to_thread(self.inventory.scan,True)
        if op not in ('manage','start','stop','restart','edit','test'):raise ValueError('invalid detected service action')
        if op=='test':
            row=await asyncio.to_thread(self.inventory.select,body['id'])
            return next((r for r in self.inventory.public()['services'] if r['id']==row['id']),{}).get('health') or {'tcp_ok':None,'udp_ok':None,'reason':'Run the paired Iran round-trip test; local process state is not end-to-end health.'}
        with self.lock:
            if self.action_busy or self.lease():raise ValueError('node is busy installing or controlling a service')
            self.action_busy=True
        try:
            if op=='manage':return await asyncio.to_thread(self.inventory.enable,body['id'],body.get('enabled'))
            if op=='edit':return await asyncio.to_thread(self.inventory.edit,body['id'],body.get('revision'),body.get('config'),body.get('ack_peer_change',False))
            return await asyncio.to_thread(self.inventory.control,body['id'],op)
        finally:
            with self.lock:self.action_busy=False

    async def external_health(self,body):
        strict_fields(body,['id'],['id']);row=await asyncio.to_thread(self.inventory.select,body['id'])
        if row.get('role')!='server':raise ValueError('foreign Paqet server required')
        cfg=load_config(self.live)
        async with self.probe_udp_lock:
            if not self.probe_udp:
                from .udp_health import Responder
                self.probe_udp=(await asyncio.get_running_loop().create_datagram_endpoint(lambda:Responder(cfg['health_key']),local_addr=('127.0.0.1',0)))[0]
        return {'key':cfg['health_key'],'tcp':cfg['health_listen'],'udp':'127.0.0.1:'+str(self.probe_udp.get_extra_info('sockname')[1])}

    def external_observation(self,pair,body):
        strict_fields(body,['server_id','time','revision','key_id','tcp_ok','udp_ok','tcp_latency_ms','udp_latency_ms','tcp_error','udp_error','reason','meaning'],['server_id','key_id','tcp_ok','udp_ok'])
        from .import_health import key_id
        row=self.inventory.select(body['server_id'])
        if row.get('role')!='server' or not key_id(row.get('config',{})) or body['key_id']!=key_id(row['config']):raise ValueError('probe belongs to another Paqet configuration')
        for key in ('tcp_ok','udp_ok'):
            if body[key] is not None and type(body[key]) is not bool:raise ValueError('invalid imported health observation')
        clean={k:body[k] for k in ('tcp_ok','udp_ok')};clean.update(time=time.time(),peer_id=pair['id'],revision=row.get('revision'))
        for k in ('tcp_latency_ms','udp_latency_ms'):
            if k in body:
                if type(body[k]) not in (int,float) or not 0<=body[k]<=60000:raise ValueError('invalid imported latency')
                clean[k]=body[k]
        with self.lock:
            if not any(p['id']==pair['id'] and not p.get('revoked') for p in self.pairs()):raise web.HTTPUnauthorized()
            self.inventory.health[row['id']]=clean
        return {'accepted':True}

    async def action(self, body):
        strict_fields(body,['unit','action'],['unit','action'])
        from .paqet import UNIT,DIAGNOSTICS,diagnostic
        if body['action'] not in ('start','stop','restart','test',*DIAGNOSTICS): raise ValueError('invalid unit action')
        if body['action'] in DIAGNOSTICS and body['unit']!=UNIT:raise ValueError('diagnostics are restricted to Paqet')
        units = read_json(self.live.parent/'install.json',{}).get('units',[])
        if body['action']=='test':
            if body['unit']!='all': raise ValueError('test uses all managed services')
        elif body['unit'] not in units or not re.fullmatch(r'donino-link(?:-[a-z0-9-]+)?\.service',body['unit']):
            raise ValueError('only managed tunnel units can be controlled')
        if body['unit']=='donino-link.service' and body['action']=='stop':
            raise ValueError('the panel and health service cannot stop itself; stop the carrier units instead')
        with self.lock:
            if self.action_busy or self.lease(): raise ValueError('node is busy installing or controlling a service')
            self.action_busy=True
            record={'id':secrets.token_hex(16),'unit':body['unit'],'action':body['action'],'created':time.time(),'status':'running'}
            records=read_json(self.root/'actions.json',[]);records.insert(0,record);atomic_json(self.root/'actions.json',records[:20])
        async def execute():
            try:
                if body['action']=='test':
                    from .health import target_status,probe
                    cfg=load_config(self.live)
                    await probe(cfg['health_listen'],cfg['health_key'],5)
                    results=await asyncio.gather(*(target_status(t) for t in cfg.get('targets',{}).values()))
                    record['targets']=dict(zip(cfg.get('targets',{}),results))
                    if not all(results): raise ValueError('some origin services are unavailable')
                elif body['action'] in DIAGNOSTICS:
                    record['result']=await asyncio.to_thread(diagnostic,body['action'],self.live.parent)
                    if not record['result']['ok']:raise ValueError('Paqet diagnostic did not complete successfully')
                else:
                    r=await asyncio.to_thread(subprocess.run,['systemctl',body['action'],body['unit']],capture_output=True,timeout=45)
                    if r.returncode: raise ValueError('systemd operation failed; check the unit journal')
                record['status']='succeeded'
            except Exception as error:
                record['status']='failed';record['error']=str(error) if isinstance(error,ValueError) else type(error).__name__
            finally:
                with self.lock:
                    records=read_json(self.root/'actions.json',[])
                    for i,row in enumerate(records):
                        if row['id']==record['id']:records[i]=record
                    atomic_json(self.root/'actions.json',records);self.action_busy=False
        task=asyncio.create_task(execute());self.tasks.add(task);task.add_done_callback(self.tasks.discard)
        return record


def application(agent, network=False):
    @web.middleware
    async def errors(request, handler):
        try:return await handler(request)
        except (ValueError,KeyError,TypeError) as error:return web.json_response({'error':str(error) if isinstance(error,ValueError) else 'invalid request'},status=400)
        except (OSError,subprocess.SubprocessError):return web.json_response({'error':'node operation failed; check the private service journal'},status=503)
    app=web.Application(client_max_size=65536,middlewares=[errors])
    if network:
        async def dispatch(request):
            source=request.remote
            body=await request.json()
            if request.path=='/exchange': result=await asyncio.to_thread(agent.exchange,body,source)
            else:
                pair=agent.authenticate(request.headers.get('Authorization',''),source)
                if request.path=='/inventory':result=await asyncio.to_thread(agent.inventory.scan,True)
                elif request.path=='/external-health':result=await agent.external_health(body)
                elif request.path=='/external-observation':result=await asyncio.to_thread(agent.external_observation,pair,body)
                elif request.path=='/telemetry': result=await asyncio.to_thread(agent.telemetry,pair,body)
                elif request.path=='/lease':result=agent.reserve(pair,body)
                elif request.path=='/release':result=agent.release(pair,body)
                else: result=await asyncio.to_thread(agent.revoke,pair['id'])
            return web.json_response(result)
        for path in ['/exchange','/telemetry','/lease','/release','/revoke-self','/inventory','/external-health','/external-observation']:app.router.add_post(path,dispatch)
    else:
        async def state(request):return web.json_response(await asyncio.to_thread(agent.state))
        async def code(request):return web.json_response(agent.pairing_code())
        async def revoke(request):
            body=await request.json();strict_fields(body,['id'],['id'])
            return web.json_response(await asyncio.to_thread(agent.revoke,body['id']))
        async def action(request):return web.json_response(await agent.action(await request.json()),status=202)
        async def imported_action(request):return web.json_response(await agent.imported_action(await request.json()))
        app.add_routes([web.post('/imported-action',imported_action),web.get('/state',state),web.post('/code',code),web.post('/revoke',revoke),web.post('/action',action)])
    return app


def initialize(port=9444):
    if os.geteuid()!=0: raise ValueError('foreign agent requires root')
    ROOT.mkdir(mode=0o700,exist_ok=True);ROOT.chmod(0o700)
    cert,key=ROOT/'agent.crt',ROOT/'agent.key'
    if not cert.exists() or not key.exists():
        subprocess.run(['openssl','req','-x509','-newkey','ed25519','-nodes','-days','3650','-subj','/CN=Donino Foreign Agent','-keyout',str(key),'-out',str(cert)],check=True,capture_output=True)
        cert.chmod(0o600);key.chmod(0o600)
    der=ssl.PEM_cert_to_DER_cert(cert.read_text())
    cfg={'port':integer(port,1024,65535,'agent port'),'ssh_port':22,'fingerprint':hashlib.sha256(der).hexdigest()}
    output=subprocess.check_output(['/usr/sbin/sshd','-T'],text=True,timeout=10)
    cfg['ssh_port']=int(next(line.split()[1] for line in output.splitlines() if line.startswith('port ')))
    atomic_json(SETTINGS,cfg)
    return cfg


def enable_agent():
    if os.geteuid()!=0 or load_config(LIVE)['role']!='foreign': raise ValueError('foreign agent belongs on the foreign root node')
    if not SETTINGS.exists(): initialize()
    text='''[Unit]
Description=Donino foreign pairing and service agent
After=network-online.target ssh.service
Wants=network-online.target ssh.service
[Service]
Type=simple
User=root
ExecStart=/opt/donino-link/current/venv/bin/donino-link foreign-agent-run
Restart=on-failure
RestartSec=5
TimeoutStopSec=60
UMask=0077
RuntimeDirectory=donino-foreign
RuntimeDirectoryMode=0750
ProtectHome=true
PrivateTmp=true
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
'''
    Path('/etc/systemd/system/donino-foreign-agent.service').write_text(text)
    subprocess.run(['systemctl','daemon-reload'],check=True)
    subprocess.run(['systemctl','enable','--now','donino-foreign-agent.service'],check=True)


async def serve_agent():
    if os.geteuid()!=0 or load_config(LIVE)['role']!='foreign': raise ValueError('foreign agent belongs on the foreign root node')
    import grp,fcntl
    lock=(ROOT/'agent.lock').open('w');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    agent=ForeignAgent()
    await asyncio.to_thread(agent.inventory.recover)
    # Repair a crash between recording a pairing/revocation and SSH reload.
    await asyncio.to_thread(agent.ssh_writer,agent.root,agent.pairs())
    records=read_json(ROOT/'actions.json',[])
    for row in records:
        if row['status']=='running':row.update(status='interrupted',error='agent restarted during the operation; inspect systemd before retrying')
    atomic_json(ROOT/'actions.json',records)
    private=web.AppRunner(application(agent),access_log=None);public=web.AppRunner(application(agent,True),access_log=None)
    await private.setup();await public.setup()
    SOCKET.parent.mkdir(mode=0o750,exist_ok=True);gid=grp.getgrnam('donino-link').gr_gid
    os.chown(SOCKET.parent,0,gid);SOCKET.parent.chmod(0o750);SOCKET.unlink(missing_ok=True)
    await web.UnixSite(private,str(SOCKET)).start();os.chown(SOCKET,0,gid);SOCKET.chmod(0o660)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(ROOT/'agent.crt',ROOT/'agent.key')
    await web.TCPSite(public,'0.0.0.0',agent.settings['port'],ssl_context=context).start()
    try:await web.TCPSite(public,'::',agent.settings['port'],ssl_context=context).start()
    except OSError:pass  # IPv6 can be disabled by the VPS operator.
    done=asyncio.Event()
    for sig in [signal.SIGTERM,signal.SIGINT]:asyncio.get_running_loop().add_signal_handler(sig,done.set)
    try:await done.wait()
    finally:
        if agent.probe_udp:agent.probe_udp.close()
        await public.cleanup();await private.cleanup()
        await asyncio.gather(*list(agent.tasks),return_exceptions=True)
        SOCKET.unlink(missing_ok=True);lock.close()
