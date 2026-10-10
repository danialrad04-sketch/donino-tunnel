"""Typed Paqet alpha.21 options and bounded, fixed-command node diagnostics."""
import copy
import ipaddress
import json
import re
import selectors
import subprocess
import time
from pathlib import Path
from .config import endpoint, loopback

VERSION = 'v1.0.0-alpha.21'
BLOCKS = ('aes', 'aes-128', 'aes-128-gcm', 'aes-192', 'salsa20', 'blowfish', 'twofish', 'cast5', '3des', 'tea', 'xtea', 'xor', 'sm4', 'none', 'null')
MODES = ('normal', 'fast', 'fast2', 'fast3', 'manual')
KCP_INTS = {'mtu': (50,1500), 'rcvwnd': (1,32768), 'sndwnd': (1,32768),
            'nodelay': (0,1), 'interval': (10,5000), 'resend': (0,2), 'nocongestion': (0,1),
            'dshard': (0,128), 'pshard': (0,128), 'smuxbuf': (1024,67108864),
            'streambuf': (1024,67108864), 'smuxkalive': (1,3600), 'smuxktimeout': (2,7200)}
LABELS = {'mtu':'MTU', 'rcvwnd':'پنجرهٔ دریافت', 'sndwnd':'پنجرهٔ ارسال', 'nodelay':'ارسال بدون تأخیر',
          'interval':'فاصلهٔ به‌روزرسانی (ms)', 'resend':'بازفرستادن سریع', 'nocongestion':'غیرفعال‌کردن کنترل ازدحام',
          'dshard':'FEC: قطعهٔ داده', 'pshard':'FEC: قطعهٔ افزونگی', 'smuxbuf':'بافر نشست (بایت)',
          'streambuf':'بافر جریان (بایت)', 'smuxkalive':'Keepalive (ثانیه)', 'smuxktimeout':'مهلت نشست (ثانیه)'}
DIAGNOSTICS = ('version', 'ping', 'dump', 'logs')
UNIT = 'donino-link-paqet.service'


def fields(value, allowed):
    if not isinstance(value, dict) or set(value)-set(allowed): raise ValueError('invalid or unknown Paqet fields')


def number(value, lo, hi, name):
    if type(value) is not int or not lo <= value <= hi: raise ValueError('invalid Paqet '+name)
    return value


def flags(value):
    if not isinstance(value,list) or not 1 <= len(value) <= 64 or any(not isinstance(v,str) or not re.fullmatch('[FSRPAUECN]{1,9}',v) for v in value):
        raise ValueError('invalid Paqet TCP flags')
    return value


def options(value=None):
    value=copy.deepcopy({} if value is None else value)
    fields(value, ('conn','kcp','log_level','pcap_sockbuf','local_flag','remote_flag','network','forwards','socks5','allow_insecure','key'))
    value['conn']=number(value.get('conn',2),1,256,'connection count')
    value['log_level']=value.get('log_level','warn')
    if value['log_level'] not in ('none','debug','info','warn','error','fatal'): raise ValueError('invalid Paqet log level')
    if type(value.get('allow_insecure',False)) is not bool: raise ValueError('Paqet insecure acknowledgment must be boolean')
    value['allow_insecure']=value.get('allow_insecure',False)
    k=value.setdefault('kcp',{})
    fields(k, (*KCP_INTS,'mode','block','wdelay','acknodelay'))
    k.setdefault('mode','normal'); k.setdefault('mtu',1150); k.setdefault('block','aes-128-gcm')
    if k['mode']=='manual':
        for name,default in [('nodelay',1),('interval',10),('resend',2),('nocongestion',0)]:k.setdefault(name,default)
    if k['mode'] not in MODES or k['block'] not in BLOCKS: raise ValueError('invalid Paqet KCP mode or encryption')
    if k['block'] in ('none','null') and not value['allow_insecure']: raise ValueError('Paqet none/null requires explicit insecure acknowledgment')
    for key,(lo,hi) in KCP_INTS.items():
        if key in k: number(k[key],lo,hi,key)
    for key in ('wdelay','acknodelay'):
        if key in k and type(k[key]) is not bool: raise ValueError('invalid Paqet '+key)
    if bool(k.get('dshard',0)) != bool(k.get('pshard',0)) or k.get('dshard',0)+k.get('pshard',0)>255: raise ValueError('Paqet FEC needs both shard counts, total <=255')
    if k.get('smuxktimeout',8)<=k.get('smuxkalive',2): raise ValueError('Paqet timeout must exceed keepalive')
    if 'key' in value and (not isinstance(value['key'],str) or not 16<=len(value['key'].encode())<=256): raise ValueError('Paqet key must be 16–256 bytes')
    if 'pcap_sockbuf' in value: number(value['pcap_sockbuf'],1024,104857600,'PCAP buffer')
    for key in ('local_flag','remote_flag'):
        if key in value: flags(value[key])
    network=value.setdefault('network',{})
    fields(network,('iran','foreign'))
    for role,row in network.items():
        fields(row,('interface','local_ip','router_mac','source_port','ipv6','ipv6_router_mac'))
        if 'interface' in row and (not isinstance(row['interface'],str) or not re.fullmatch('[A-Za-z0-9_.:-]{1,15}',row['interface'])): raise ValueError('invalid Paqet interface')
        for key in ('local_ip','ipv6'):
            if key in row:
                try: addr=ipaddress.ip_address(row[key])
                except (ValueError,TypeError): raise ValueError('invalid Paqet local IP') from None
                if addr.is_unspecified or addr.is_multicast or (key=='ipv6' and addr.version!=6): raise ValueError('invalid Paqet local IP')
        for key in ('router_mac','ipv6_router_mac'):
            if key in row and (not isinstance(row[key],str) or not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}',row[key])): raise ValueError('invalid Paqet router MAC')
        if 'source_port' in row:
            if role!='iran': raise ValueError('Paqet source port belongs to Iran/client')
            number(row['source_port'],0,65535,'source port')
            if row['source_port'] and value['conn']!=1: raise ValueError('fixed Paqet client source port requires conn=1')
        if ('ipv6' in row) != ('ipv6_router_mac' in row): raise ValueError('additional IPv6 address requires its router MAC')
    forwards=value.setdefault('forwards',[])
    if not isinstance(forwards,list) or len(forwards)>40: raise ValueError('maximum 40 additional Paqet forwards')
    listeners=set()
    for row in forwards:
        fields(row,('listen','target','protocol'))
        if set(row)!= {'listen','target','protocol'} or row['protocol'] not in ('tcp','udp'): raise ValueError('Paqet forwards require TCP or UDP')
        host,port=endpoint(row['listen']); ipaddress.ip_address(host)
        if not loopback(row['target']): raise ValueError('Paqet forward targets must be literal foreign loopback IPs')
        key=(row['protocol'],port)
        if key in listeners: raise ValueError('duplicate Paqet forward listener')
        listeners.add(key)
    socks=value.setdefault('socks5',[])
    if not isinstance(socks,list) or len(socks)>8: raise ValueError('maximum 8 Paqet SOCKS5 listeners')
    for row in socks:
        fields(row,('listen','username','password'))
        host,port=endpoint(row.get('listen')); ipaddress.ip_address(host)
        for key in ('username','password'):
            row.setdefault(key,'')
            if not isinstance(row[key],str) or len(row[key].encode())>255: raise ValueError('invalid Paqet SOCKS5 credentials')
        if bool(row['username'])!=bool(row['password']): raise ValueError('SOCKS5 username and password must be set together')
        if not loopback(row['listen']) and not row['username']: raise ValueError('public SOCKS5 requires authentication')
        if ('tcp',port) in listeners: raise ValueError('duplicate Paqet SOCKS5/TCP listener')
        listeners.add(('tcp',port))
    return value


def safe_options(value):
    result=copy.deepcopy(value)
    result.pop('key',None)
    for row in result.get('socks5',[]):
        row['authenticated']=bool(row.pop('password',''))
    return result


def capabilities():
    return {'version':VERSION,'protocols':['kcp'],'forward_protocols':['tcp','udp'],'modes':list(MODES),
            'blocks':list(BLOCKS),'kcp_numbers':{k:{'min':lo,'max':hi,'label':LABELS[k]} for k,(lo,hi) in KCP_INTS.items()},
            'actions':['start','stop','restart',*DIAGNOSTICS], 'scope':'Linux amd64/arm64; fixed verified release'}


def status(node):
    node=Path(node); file=node/'transports/paqet.yaml'
    if not file.exists(): return {'installed':False,'version':VERSION}
    cfg=json.loads(file.read_text()); t=cfg.get('transport',{}); k=dict(t.get('kcp',{})); k.pop('key',None)
    return {'installed':True,'version':VERSION,'role':cfg['role'],'transport':t.get('protocol'),
            'conn':t.get('conn',1),'kcp':k,'network':cfg.get('network'),
            'server':cfg.get('server',cfg.get('listen')),'forwards':cfg.get('forward',[]),
            'socks5':[{'listen':r['listen'],'username':r.get('username',''),'authenticated':bool(r.get('password'))} for r in cfg.get('socks5',[])],
            'notice':'UDP/direct forwards and SOCKS5 bypass gateway selection and gateway traffic counters; Paqet ping only confirms packet sending.'}


def diagnostic(action,node, binary='/opt/donino-link/current/bin/paqet'):
    node=Path(node); metadata=json.loads((node/'install.json').read_text())
    if UNIT not in metadata.get('units',[]): raise ValueError('Paqet is not installed')
    cfg=json.loads((node/'transports/paqet.yaml').read_text())
    if action not in DIAGNOSTICS: raise ValueError('invalid Paqet diagnostic')
    if action=='ping' and cfg['role']!='client': raise ValueError('Paqet ping is an Iran/client command')
    if action=='dump' and cfg['role']!='server': raise ValueError('Paqet dump is a foreign/server command')
    argv=['journalctl','-u',UNIT,'-n','60','--no-pager','--output=short-iso'] if action=='logs' else [binary,action]
    if action in ('ping','dump'): argv+=['-c',str(node/'transports/paqet.yaml')]
    limit=65536; raw=bytearray(); timed=False; deadline=time.monotonic()+(3 if action=='dump' else 8)
    with subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.STDOUT) as process:
        selector=selectors.DefaultSelector(); selector.register(process.stdout,selectors.EVENT_READ)
        try:
            while len(raw)<limit:
                remaining=deadline-time.monotonic()
                if remaining<=0: timed=True; break
                ready=selector.select(min(remaining,.2))
                if ready:
                    chunk=process.stdout.read1(min(8192,limit-len(raw)))
                    if not chunk: break
                    raw.extend(chunk)
                elif process.poll() is not None: break
        finally:
            selector.close()
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=1)
                except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=1)
        code=process.returncode
    output=raw.decode(errors='replace')
    for secret in [cfg.get('transport',{}).get('kcp',{}).get('key',''), *[r.get('password','') for r in cfg.get('socks5',[])]]:
        if secret: output=output.replace(secret,'[redacted]')
    output='\n'.join('[redacted sensitive line]' if re.search(r'(?i)\b(password|secret|token|private.key)\b',line) else line for line in output.splitlines())
    return {'action':action,'ok':(action=='dump' and (timed or len(raw)>=limit)) or code==0,'exit_code':code,
            'time_limited':timed,'truncated':len(raw)>=limit,'output':output,
            'meaning':'packet sent; not a round-trip health test' if action=='ping' else 'bounded diagnostic only; tunnel health is reported separately'}
