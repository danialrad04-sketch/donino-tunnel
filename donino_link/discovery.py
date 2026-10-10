"""Passive systemd inventory and explicitly adopted Paqet installations.

No discovered service is enabled, restarted, rewritten or installed by scanning.
Paths/commands always come from the local service, never from the HTTP request.
"""
import copy
import hashlib
import ipaddress
import json
import os
import re
import selectors
import shlex
import socket
import stat
import subprocess
import tempfile
import time
import threading
from functools import wraps
from .import_health import key_id
from pathlib import Path
import yaml
from .paqet import KCP_INTS, MODES, BLOCKS, flags, number
from .config import endpoint, loopback, atomic_json

UNIT_RE=re.compile(r'[A-Za-z0-9_.@\\:-]{1,180}\.service')
SECRET=re.compile(r'(?i)(password|secret|token|private.?key|^key$)')
REDACTED='[redacted]'


def bounded(argv,seconds=5,limit=262144):
    raw=bytearray();deadline=time.monotonic()+seconds
    with subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.STDOUT) as p:
        eof=False;selector=selectors.DefaultSelector();selector.register(p.stdout,selectors.EVENT_READ)
        try:
            while len(raw)<limit and time.monotonic()<deadline:
                if selector.select(min(.2,max(0,deadline-time.monotonic()))):
                    chunk=p.stdout.read1(min(8192,limit-len(raw)))
                    if not chunk:eof=True;break
                    raw.extend(chunk)
                elif p.poll() is not None:break
        finally:
            selector.close()
            if eof and p.poll() is None:
                try:p.wait(timeout=max(.01,deadline-time.monotonic()))
                except subprocess.TimeoutExpired:pass
            if p.poll() is None:
                p.terminate()
                try:p.wait(timeout=1)
                except subprocess.TimeoutExpired:p.kill();p.wait(timeout=1)
    return p.returncode,raw.decode(errors='replace'),len(raw)>=limit


def read_config(path):
    path=Path(path)
    if not path.is_file() or path.stat().st_size>262144:raise ValueError('configuration must be a regular file <=256 KiB')
    raw=path.read_bytes()
    try:
        # Reject YAML alias expansion and deeply nested/large documents before loading.
        depth=0;events=0
        for event in yaml.parse(raw,Loader=yaml.SafeLoader):
            events+=1
            if isinstance(event,yaml.events.AliasEvent):raise ValueError('YAML aliases are not supported')
            if isinstance(event,(yaml.events.MappingStartEvent,yaml.events.SequenceStartEvent)):depth+=1
            if isinstance(event,(yaml.events.MappingEndEvent,yaml.events.SequenceEndEvent)):depth-=1
            if depth>20 or events>10000:raise ValueError('configuration is too complex')
        cfg=yaml.safe_load(raw)
    except yaml.YAMLError:raise ValueError('configuration YAML/JSON could not be parsed') from None
    if not isinstance(cfg,dict):raise ValueError('configuration must be a mapping')
    return cfg,raw


def safe(value):
    if isinstance(value,dict):return {str(k):(REDACTED if SECRET.search(str(k)) else safe(v)) for k,v in value.items()}
    if isinstance(value,list):return [safe(v) for v in value]
    if value is None or type(value) in (str,int,float,bool):return value
    return str(value)


def restore_secrets(new,old):
    if isinstance(new,dict):
        result={}
        for k,v in new.items():
            previous=old.get(k) if isinstance(old,dict) else None
            if SECRET.search(str(k)) and v==REDACTED:
                if previous is None:raise ValueError('a new secret needs an explicit value')
                result[k]=previous
            else:result[k]=restore_secrets(v,previous)
        return result
    if isinstance(new,list):
        # Match SOCKS/forward rows by listen address, so reorder never swaps passwords.
        previous=old if isinstance(old,list) else []
        return [restore_secrets(v,next((p for p in previous if isinstance(p,dict) and p.get('listen')==v.get('listen')),{})) if isinstance(v,dict) and 'listen' in v else restore_secrets(v,previous[i] if i<len(previous) else None) for i,v in enumerate(new)]
    return new


def known_engine(argv,unit):
    for argument in argv[:1]:
        name=Path(argument).name.lower()
        if re.fullmatch(r'paqet(?:[_-](?:linux|amd64|arm64|x86_64|aarch64)[A-Za-z0-9_-]*)?',name):return 'paqet'
        for engine,names in [('frp',('frpc','frps')),('backpack',('backpack',)),('backhaul',('backhaul',)),('xray',('xray',)),('wireguard',('wg-quick',))]:
            if name in names:return engine
    if unit.startswith('donino-link-'):
        for engine in ('browser-wss','donino-mux','donino-continuum'):
            if unit=='donino-link-'+engine+'.service':return engine
    return None


def config_arg(argv,working):
    path=None
    for i,arg in enumerate(argv):
        if arg in ('-c','--config') and i+1<len(argv):path=argv[i+1];break
        if arg.startswith('--config='):path=arg.split('=',1)[1];break
        if arg.startswith('-c='):path=arg[3:];break
    if not path:return None
    file=Path(path)
    if not file.is_absolute():file=Path(working or '/')/file
    return str(file.resolve())


def validate_paqet(cfg):
    def fields(value,allowed):
        if not isinstance(value,dict) or set(value)-set(allowed):raise ValueError('unsupported Paqet fields; nothing was changed')
    fields(cfg,('role','log','listen','socks5','forward','network','server','transport'))
    if cfg.get('role') not in ('client','server'):raise ValueError('Paqet role must be client or server')
    fields(cfg.get('log',{}),('level',))
    if cfg.get('log',{}).get('level','none') not in ('none','debug','info','warn','error','fatal'):raise ValueError('invalid log level')
    transport=cfg.get('transport',{});fields(transport,('protocol','conn','kcp'))
    if transport.get('protocol','kcp')!='kcp':raise ValueError('only KCP is supported by this importer')
    conn=transport.get('conn',1) or 1;number(conn,1,256,'connection count')
    k=transport.get('kcp',{});fields(k,(*KCP_INTS,'mode','block','key','wdelay','acknodelay'))
    if k.get('mode','fast') not in MODES or k.get('block','aes') not in BLOCKS:raise ValueError('invalid KCP mode or block')
    if k.get('block','aes') not in ('none','null') and (not isinstance(k.get('key'),str) or not 1<=len(k['key'].encode())<=256):raise ValueError('an encryption key is required')
    defaults=('mtu','rcvwnd','sndwnd','smuxbuf','streambuf','smuxkalive','smuxktimeout')
    for name,(lo,hi) in KCP_INTS.items():
        if name in k:
            if name in defaults and k[name]==0 and type(k[name]) is int:continue
            number(k[name],lo,hi,name)
    for name in ('wdelay','acknodelay'):
        if name in k and type(k[name]) is not bool:raise ValueError('invalid KCP boolean')
    if bool(k.get('dshard',0))!=bool(k.get('pshard',0)) or k.get('dshard',0)+k.get('pshard',0)>255:raise ValueError('invalid FEC shard pair')
    if (k.get('smuxktimeout') or 8)<=(k.get('smuxkalive') or 2):raise ValueError('timeout must exceed keepalive')
    network=cfg.get('network',{});fields(network,('interface','guid','ipv4','ipv6','pcap','tcp'))
    if not isinstance(network.get('interface'),str) or not re.fullmatch('[A-Za-z0-9_.:-]{1,15}',network['interface']):raise ValueError('invalid network interface')
    ports=[]
    for family in ('ipv4','ipv6'):
        row=network.get(family)
        if row is None:continue
        fields(row,('addr','router_mac'))
        # Native Paqet allows a zero/random client source port.
        address=row.get('addr','');host,sep,p=address.rpartition(':');host=host.strip('[]')
        if not sep or not p.isdigit() or not 0<=int(p)<=65535 or ipaddress.ip_address(host).version!=int(family[-1]):raise ValueError('invalid Paqet local address')
        if not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}',row.get('router_mac','')):raise ValueError('invalid router MAC')
        ports.append(int(p))
    if not ports or len(set(ports))!=1 or (cfg['role']=='client' and conn>1 and ports[0]):raise ValueError('invalid Paqet address family/source port combination')
    pcap=network.get('pcap',{});fields(pcap,('sockbuf',))
    if pcap.get('sockbuf'):number(pcap['sockbuf'],1024,104857600,'PCAP buffer')
    tcp=network.get('tcp',{});fields(tcp,('local_flag','remote_flag'))
    for f in tcp:flags(tcp[f])
    bind=cfg.get('server' if cfg['role']=='client' else 'listen',{});fields(bind,('addr',))
    address=bind.get('addr','')
    if cfg['role']=='server' and address.startswith(':'):endpoint('0.0.0.0'+address)
    else:endpoint(address)
    listeners=set()
    forwards=cfg.get('forward',[]);socks=cfg.get('socks5',[])
    if not isinstance(forwards,list) or len(forwards)>80 or not isinstance(socks,list) or len(socks)>16:raise ValueError('too many or invalid listeners')
    for row in forwards:
        fields(row,('listen','target','protocol'));endpoint(row['target'])
        proto=row.get('protocol','tcp')
        if proto not in ('tcp','udp'):raise ValueError('invalid forward protocol')
        key=(proto,endpoint('0.0.0.0'+row['listen'] if row['listen'].startswith(':') else row['listen'])[1])
        if key in listeners:raise ValueError('duplicate listener')
        listeners.add(key)
    for row in socks:
        fields(row,('listen','username','password'))
        key=('tcp',endpoint('0.0.0.0'+row['listen'] if row['listen'].startswith(':') else row['listen'])[1])
        if key in listeners:raise ValueError('duplicate SOCKS/TCP listener')
        listeners.add(key)
        for field in ('username','password'):
            if not isinstance(row.get(field,''),str) or len(row.get(field,'').encode())>255:raise ValueError('invalid SOCKS credentials')
        if bool(row.get('username'))!=bool(row.get('password')):raise ValueError('SOCKS credentials must be paired')
    return cfg


def root_owned(info):
    return info.st_uid==0 and not info.st_mode&0o022


def synchronized(method):
    @wraps(method)
    def wrapped(self,*args,**kwargs):
        with self.lock:return method(self,*args,**kwargs)
    return wrapped


class Inventory:
    def __init__(self,root,live):
        self.root,self.live=Path(root),Path(live);self.rows={};self.checked=0;self.last_scan_time=0;self.error='';self.recovery_error='';self.health={};self.lock=threading.RLock()
    @synchronized
    def scan(self,force=False):
        if not force and time.monotonic()-self.checked<8:return self.public()
        rows={};self.checked=time.monotonic()
        try:
            code,listing,_=bounded(['systemctl','list-unit-files','--type=service','--no-legend','--no-pager'])
            if code:raise ValueError('systemd inventory is unavailable')
            units=[line.split()[0] for line in listing.splitlines() if line.split() and UNIT_RE.fullmatch(line.split()[0])][:512]
            # Include transient/running instances that have no standalone unit file.
            code,running,_=bounded(['systemctl','list-units','--type=service','--all','--plain','--no-legend','--no-pager'])
            if not code:units=sorted(set(units)|{line.split()[0] for line in running.splitlines() if line.split() and UNIT_RE.fullmatch(line.split()[0])})[:512]
            units=[unit for unit in units if not unit.endswith('@.service')]
            partial=False
            if units:
                code,details,truncated=bounded(['systemctl','show','--no-pager','--property=Id,ExecStart,WorkingDirectory,MainPID,ActiveState,SubState,UnitFileState,FragmentPath,MemoryCurrent,NRestarts,ControlGroup',*units],limit=1048576)
                if truncated or (code and not re.search(r'^Id=',details,re.M)):raise ValueError('systemd details are unavailable or too large')
                partial=bool(code)
                for block in details.split('\n\n'):
                    props=dict(line.split('=',1) for line in block.splitlines() if '=' in line)
                    unit=props.get('Id','')
                    if not UNIT_RE.fullmatch(unit):continue
                    child_pid=None;argv=[];pid=int(props.get('MainPID','0') or 0)
                    if pid:
                        try:argv=[v.decode() for v in (Path('/proc')/str(pid)/'cmdline').read_bytes().split(b'\0') if v]
                        except (OSError,UnicodeError):pass
                    if not argv:
                        match=re.search(r'argv\[\]=(.*?) ;',props.get('ExecStart',''))
                        if match:
                            try:argv=shlex.split(match[1])
                            except ValueError:continue
                    engine=known_engine(argv,unit)
                    if not engine and props.get('ControlGroup','').startswith('/'):
                        try:
                            ids=(Path('/sys/fs/cgroup')/props['ControlGroup'].lstrip('/')/'cgroup.procs').read_text().split()[:32]
                            for child in ids:
                                child_argv=[v.decode() for v in (Path('/proc')/child/'cmdline').read_bytes().split(b'\0') if v]
                                child_engine=known_engine(child_argv,unit)
                                if child_engine:argv=child_argv;engine=child_engine;child_pid=int(child);break
                        except (OSError,UnicodeError):pass
                    if not engine and 'paqet' in unit.lower():engine='paqet-unconfirmed'
                    if not engine:continue
                    file=config_arg(argv,props.get('WorkingDirectory')) if engine=='paqet' else None
                    binary=str(Path(argv[0]).resolve()) if argv and Path(argv[0]).is_absolute() else None
                    identity=hashlib.sha256(unit.encode()).hexdigest()[:24]
                    row={'id':identity,'unit':unit,'engine':engine,'active':props.get('ActiveState')=='active','state':props.get('ActiveState','unknown'),
                         'process_pid':child_pid or pid,'pid':pid,'enabled':props.get('UnitFileState','unknown'),'memory':int(props['MemoryCurrent']) if props.get('MemoryCurrent','').isdigit() and int(props['MemoryCurrent'])<2**64-1 else None,
                         'restarts':int(props.get('NRestarts','0')),'config_path':file,'binary':binary,'argv':argv,
                         'descriptor':hashlib.sha256(json.dumps([unit,file,binary,argv]).encode()).hexdigest(),
                         'managed_by_donino':unit.startswith('donino-link-'),'config_error':None}
                    if file:
                        try:
                            cfg,raw=read_config(file)
                            if cfg.get('role') not in ('client','server'):raise ValueError('Paqet configuration role is missing')
                            row.update(config=cfg,revision=hashlib.sha256(raw).hexdigest(),role=cfg['role'])
                            validate_paqet(cfg)
                            row['editable']=True
                        except (ValueError,KeyError,TypeError,OSError) as error:
                            row['editable']=False;row['config_error']=str(error) if isinstance(error,ValueError) else 'configuration is inaccessible or unsupported'
                    rows[identity]=row
            self.rows=rows;self.error='Some systemd units could not be inspected; discovered units are shown.' if partial else ''
            self.processes();self.last_scan_time=time.time()
        except (OSError,ValueError,subprocess.SubprocessError) as error:
            self.error=str(error) if isinstance(error,ValueError) else 'systemd detection failed'
        return self.public()
    def processes(self):
        """Read-only fallback for direct processes launched without systemd."""
        represented={row.get('process_pid',row['pid']) for row in self.rows.values()}
        for file in list(Path('/proc').glob('[0-9]*/cmdline'))[:2048]:
            try:
                pid=int(file.parent.name)
                if pid in represented:continue
                with file.open('rb') as stream:raw=stream.read(32768)
                argv=[part.decode() for part in raw.split(b'\0') if part]
                engine=known_engine(argv,'')
                if not engine:continue
                # Processes inside systemd service cgroups are already scanned,
                # including child workers. Do not offer duplicate controls.
                group=(file.parent/'cgroup').read_text()
                if re.search(r'/[^/\n]+\.service(?:/|$)',group):continue
                working=os.readlink(file.parent/'cwd')
                identity=hashlib.sha256(('process:'+str(pid)+':'+str(argv)).encode()).hexdigest()[:24]
                row={'id':identity,'unit':'process:'+str(pid),'engine':engine,'pid':pid,'active':True,'state':'running','source':'process',
                     'enabled':'unmanaged','memory':None,'restarts':None,'config_path':config_arg(argv,working) if engine=='paqet' else None,
                     'managed_by_donino':False,'editable':False,'config_error':None,'descriptor':None}
                if row['config_path']:
                    cfg,data=read_config(row['config_path']);row.update(config=cfg,role=cfg.get('role'),revision=hashlib.sha256(data).hexdigest())
                self.rows[identity]=row
            except (OSError,ValueError,UnicodeError):continue
    @synchronized
    def registry(self):
        file=self.root/'adopted-services.json'
        return json.loads(file.read_text()) if file.exists() else {}
    @synchronized
    def public(self):
        grants=self.registry();rows=[]
        for row in self.rows.values():
            public={k:v for k,v in row.items() if k not in ('argv','descriptor','binary','config')}
            public['management_enabled']=bool(row.get('descriptor') and grants.get(row['id'])==row['descriptor'])
            if 'config' in row:public['config']=safe(row['config']);public['key_id']=key_id(row['config'])
            observation=self.health.get(row['id'])
            public['health']=observation if observation and row['active'] and observation.get('revision')==row.get('revision') and 0<=time.time()-observation['time']<45 else None
            rows.append(public)
        return {'services':rows,'checked_at':self.last_scan_time,'error':self.recovery_error or self.error,'mode':'passive; no service mutations'}
    @synchronized
    def select(self,identity,managed=False):
        if not isinstance(identity,str) or not re.fullmatch('[a-f0-9]{24}',identity):raise ValueError('invalid detected service ID')
        self.scan(force=managed)
        row=self.rows.get(identity)
        if not row or row['engine']!='paqet':raise ValueError('detected Paqet service not found')
        if managed and (not row.get('descriptor') or self.registry().get(identity)!=row['descriptor']):raise ValueError('enable management of this detected service first')
        return row
    @synchronized
    def enable(self,identity,enabled):
        if type(enabled) is not bool:raise ValueError('enabled must be boolean')
        self.scan(True)
        row=self.select(identity);grants=self.registry()
        if row.get('source')=='process':raise ValueError('standalone processes are read-only; service management requires systemd')
        if enabled:
            if not row.get('editable') or not row.get('binary') or not Path(row['binary']).is_file():raise ValueError('direct Paqet executable/config required for management')
            for file in (Path(row['binary']),Path(row['config_path'])):
                info=file.stat()
                if not root_owned(info):raise ValueError('management requires root-owned files without group/world write access')
            grants[identity]=row['descriptor']
        else:grants.pop(identity,None)
        atomic_json(self.root/'adopted-services.json',grants)
        return {'ok':True,'changed_service':False,'management_enabled':enabled}
    @synchronized
    def logs(self,identity,cursor=None):
        row=self.select(identity)
        if row.get('source')=='process':return {'ok':True,'cursor':None,'lines':[],'reason':'Standalone process has no systemd journal; configure a service before log/control management.'}
        if cursor is not None and (not isinstance(cursor,str) or not re.fullmatch('[A-Za-z0-9;=_:-]{1,1024}',cursor)):raise ValueError('invalid journal cursor')
        args=['journalctl','-u',row['unit'],'--no-pager','--output=json','-n','80']
        if cursor:args.append('--after-cursor='+cursor)
        code,output,truncated=bounded(args,limit=131072)
        lines=[];last=cursor
        secrets=secret_values(row.get('config',{}))
        for line in output.splitlines():
            try:event=json.loads(line)
            except ValueError:continue
            last=event.get('__CURSOR',last);message=event.get('MESSAGE','')
            if not isinstance(message,str):message='[binary journal message]'
            for secret in secrets:message=message.replace(secret,REDACTED)
            if SECRET.search(message):message='[redacted sensitive line]'
            lines.append({'time':event.get('__REALTIME_TIMESTAMP'),'message':message[:2000]})
        return {'ok':code==0,'cursor':last,'lines':lines,'truncated':truncated}
    @synchronized
    def control(self,identity,action):
        row=self.select(identity,managed=True)
        if action not in ('start','stop','restart'):raise ValueError('invalid imported service operation')
        code,_,_=bounded(['systemctl',action,row['unit']],seconds=30,limit=16384)
        if code:raise ValueError('service operation failed; inspect live journal')
        self.checked=0
        return {'ok':True,'unit':row['unit'],'action':action}
    @synchronized
    def edit(self,identity,revision,value,ack_peer_change=False):
        if (self.root/'import-edit.json').exists():raise ValueError('pending edit recovery must be resolved before another edit')
        row=self.select(identity,managed=True)
        if row.get('managed_by_donino'):raise ValueError('use the coordinated Donino reinstall form for managed tunnel configurations')
        if not row.get('editable') or revision!=row.get('revision'):raise ValueError('configuration changed; reload before saving')
        cfg=restore_secrets(copy.deepcopy(value),row['config']);validate_paqet(cfg)
        if cfg['role']!=row['config']['role']:raise ValueError('changing the node role is not supported')
        # Changes to the transport contract need coordinated changes on both nodes.
        if cfg.get('transport',{})!=row['config'].get('transport',{}) or cfg.get('server')!=row['config'].get('server') or cfg.get('listen')!=row['config'].get('listen'):
            if ack_peer_change is not True:raise ValueError('confirm that peer parameters must match before changing transport/key/peer settings')
        file=Path(row['config_path']);old=file.read_bytes()
        if hashlib.sha256(old).hexdigest()!=revision:raise ValueError('configuration changed while saving')
        info=file.stat()
        if not root_owned(info):raise ValueError('configuration permissions changed')
        backup=self.root/'import-backups'/row['id'];backup.mkdir(parents=True,exist_ok=True,mode=0o700)
        stamp=str(time.time_ns());original=backup/(stamp+'.original')
        with original.open('wb') as stream:
            os.fchmod(stream.fileno(),0o600);stream.write(old);stream.flush();os.fsync(stream.fileno())
        directory=os.open(backup,os.O_DIRECTORY)
        try:os.fsync(directory)
        finally:os.close(directory)
        new=(json.dumps(cfg,ensure_ascii=False,indent=2)+'\n').encode()
        journal={'old_hash':hashlib.sha256(old).hexdigest(),'new_hash':hashlib.sha256(new).hexdigest(),'unit':row['unit'],'config_path':str(file),'backup':str(backup/(stamp+'.original')),'active':row['active'],'mode':stat.S_IMODE(info.st_mode),'uid':info.st_uid,'gid':info.st_gid}
        marker=self.root/'import-edit.json';atomic_json(marker,journal)
        try:
            replace_bytes(file,new,info)
            if row['active']:
                code,_,_=bounded(['systemctl','restart',row['unit']],seconds=30)
                if code:raise ValueError('service restart failed')
                time.sleep(.5)
                code,_,_=bounded(['systemctl','is-active','--quiet',row['unit']])
                if code:raise ValueError('edited service did not stay active')
        except BaseException:
            replace_bytes(file,old,info)
            if row['active']:
                code,_,_=bounded(['systemctl','restart',row['unit']],seconds=30)
                if code:
                    self.recovery_error='original configuration restored but restart failed; pending recovery retained'
                    self.checked=0
                    raise ValueError('original configuration restored, but service restart failed; recovery marker retained; inspect journal') from None
            marker.unlink(missing_ok=True);self.checked=0
            raise
        marker.unlink(missing_ok=True)
        for previous in sorted(backup.glob('*.original'))[:-10]:previous.unlink()
        self.checked=0
        return {'ok':True,'restarted':row['active'],'backup_saved':True,'round_trip_verified':False}
    @synchronized
    def recover(self):
        marker=self.root/'import-edit.json'
        if not marker.exists():return
        journal=json.loads(marker.read_text());file=Path(journal['config_path']);info=file.stat()
        current=hashlib.sha256(file.read_bytes()).hexdigest()
        if current not in (journal.get('old_hash'),journal.get('new_hash')):
            self.recovery_error='pending edit recovery conflicts with a later operator change; no configuration was overwritten'
            return
        original=Path(journal['backup']).read_bytes()
        if hashlib.sha256(original).hexdigest()!=journal.get('old_hash'):
            self.recovery_error='edit recovery backup checksum mismatch; no configuration was overwritten'
            return
        replace_bytes(file,original,info)
        if journal['active']:
            code,_,_=bounded(['systemctl','restart',journal['unit']],seconds=30)
            if code:
                self.recovery_error='edit recovery restored configuration but service restart failed; inspect journal'
                return
        marker.unlink();self.recovery_error=''


def replace_bytes(file,data,info):
    fd,name=tempfile.mkstemp(prefix='.donino-import-',dir=file.parent)
    try:
        with os.fdopen(fd,'wb') as stream:
            os.fchmod(stream.fileno(),stat.S_IMODE(info.st_mode));os.fchown(stream.fileno(),info.st_uid,info.st_gid)
            stream.write(data);stream.flush();os.fsync(stream.fileno())
        os.replace(name,file)
        directory=os.open(file.parent,os.O_DIRECTORY)
        try:os.fsync(directory)
        finally:os.close(directory)
    finally:
        if os.path.exists(name):os.unlink(name)


def secret_values(cfg):
    result=[]
    if isinstance(cfg,dict):
        for k,v in cfg.items():
            if SECRET.search(str(k)) and isinstance(v,str) and v:result.append(v)
            else:result+=secret_values(v)
    elif isinstance(cfg,list):
        for row in cfg:result+=secret_values(row)
    return result
