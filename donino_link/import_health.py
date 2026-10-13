"""Use an existing SOCKS5 listener to test a paired foreign Donino responder.
No forward/config is added to Paqet. Results are not inferred from process state.
"""
import hashlib
import hmac
import json
import secrets
import socket
import struct
import time
from .config import endpoint,loopback
from .health import mac


def key_id(cfg):
    key=cfg.get('transport',{}).get('kcp',{}).get('key','')
    return hashlib.sha256(('donino-paqet-pair:'+key).encode()).hexdigest() if isinstance(key,str) and key else None


def recv(conn,n):
    data=bytearray()
    while len(data)<n:
        part=conn.recv(n-len(data))
        if not part:raise ValueError('SOCKS connection closed')
        data.extend(part)
    return bytes(data)


def address(host,port):
    try:raw=socket.inet_pton(socket.AF_INET,host);family=1
    except OSError:raw=socket.inet_pton(socket.AF_INET6,host);family=4
    return bytes([family])+raw+struct.pack('!H',port)


def socks(row,command,target):
    host,port=endpoint('0.0.0.0'+row['listen'] if row['listen'].startswith(':') else row['listen'])
    if host in ('0.0.0.0','::'):host='127.0.0.1' if host=='0.0.0.0' else '::1'
    # A discovered listener bound to another local interface is not a remote proxy.
    conn=socket.create_connection((host,port),timeout=3);conn.settimeout(3)
    try:
        user=row.get('username','').encode();password=row.get('password','').encode();method=2 if user else 0
        conn.sendall(bytes([5,1,method]));reply=recv(conn,2)
        if reply!=bytes([5,method]):raise ValueError('SOCKS method rejected')
        if user:
            conn.sendall(bytes([1,len(user)])+user+bytes([len(password)])+password)
            if recv(conn,2)!=b'\x01\x00':raise ValueError('SOCKS authentication rejected')
        conn.sendall(bytes([5,command,0])+address(*target));reply=recv(conn,4)
        if reply[:3]!=b'\x05\x00\x00':raise ValueError('SOCKS CONNECT/UDP_ASSOCIATE failed')
        if reply[3]==1:bind_host=socket.inet_ntop(socket.AF_INET,recv(conn,4))
        elif reply[3]==4:bind_host=socket.inet_ntop(socket.AF_INET6,recv(conn,16))
        else:raise ValueError('unexpected SOCKS relay address')
        bind_port=struct.unpack('!H',recv(conn,2))[0]
        if bind_host in ('0.0.0.0','::'):bind_host=host
        return conn,(bind_host,bind_port)
    except BaseException:conn.close();raise


def test(cfg,material):
    rows=cfg.get('socks5',[])
    if cfg.get('role')!='client' or not rows:
        result=forward_diagnostics(cfg,material.get('targets',[]))
        result.update(tcp_ok=None,udp_ok=None,verification='diagnostics-only',
                      reason='Existing forwards checked without changing Paqet. No SOCKS5 route reaches the signed responder, so TCP/UDP carrier round trips remain unverified.')
        return result
    key=material['key'];tcp_address=material['tcp'];udp_address=material['udp']
    if not loopback(tcp_address) or not loopback(udp_address):raise ValueError('paired probe targets must be loopback')
    result={'tcp_ok':False,'udp_ok':False,'verification':'signed-round-trip','meaning':'Fresh signed round trips through the existing Paqet SOCKS5 listener, not origin/VPN application health.'}
    row=rows[0]
    start=time.monotonic()
    try:
        control,_=socks(row,1,endpoint(tcp_address))
        with control:
            nonce=secrets.token_hex(32)
            control.sendall((json.dumps({'nonce':nonce,'auth':mac(key,'probe:'+nonce)})+'\n').encode())
            raw=bytearray();deadline=time.monotonic()+3
            while len(raw)<8192:
                remaining=deadline-time.monotonic()
                if remaining<=0:raise ValueError('TCP health response timed out')
                control.settimeout(remaining);byte=control.recv(1)
                if not byte:raise ValueError('probe response closed')
                raw.extend(byte)
                if byte==b'\n':break
            packet=json.loads(raw);body=json.loads(packet['body'])
            if not hmac.compare_digest(mac(key,packet['body']),packet['auth']) or body['nonce']!=nonce:raise ValueError('invalid TCP health signature/nonce')
            result.update(tcp_ok=True,tcp_latency_ms=round((time.monotonic()-start)*1000,3))
    except (OSError,ValueError,KeyError,TypeError):result['tcp_error']='TCP signed round trip failed'
    start=time.monotonic()
    try:
        control,relay=socks(row,3,('0.0.0.0',0))
        family=socket.AF_INET6 if ':' in relay[0] else socket.AF_INET
        with control,socket.socket(family,socket.SOCK_DGRAM) as udp:
            udp.settimeout(3);udp.connect(relay);nonce=secrets.token_hex(32)
            header=b'\x00\x00\x00'+address(*endpoint(udp_address))
            udp.send(header+json.dumps({'nonce':nonce,'auth':mac(key,'udp-probe:'+nonce)}).encode())
            raw=udp.recv(4096)
            if not raw.startswith(header):raise ValueError('unexpected SOCKS UDP header')
            packet=json.loads(raw[len(header):])
            if packet['nonce']!=nonce or not hmac.compare_digest(mac(key,'udp-reply:'+nonce),packet['auth']):raise ValueError('invalid UDP health signature/nonce')
            result.update(udp_ok=True,udp_latency_ms=round((time.monotonic()-start)*1000,3))
    except (OSError,ValueError,KeyError,TypeError):result['udp_error']='UDP signed round trip failed'
    return result


def forward_diagnostics(cfg,targets=()):
    """Opening an existing local forward is NOT evidence of origin delivery."""
    listeners=[]
    if cfg.get('role')=='client':
        for row in cfg.get('forward',[])[:32]:
            if row.get('protocol','tcp')!='tcp':continue
            address=row.get('listen','');host,port=endpoint('0.0.0.0'+address if address.startswith(':') else address)
            if host in ('0.0.0.0','::'):host='127.0.0.1' if host=='0.0.0.0' else '::1'
            reachable=False
            try:
                with socket.create_connection((host,port),timeout=.5):reachable=True
            except OSError:pass
            listeners.append({'listen':address,'target':row.get('target'),'tcp_accepting':reachable})
    return {'local_listeners':listeners,'origin_targets':list(targets),
            'meaning':'Local TCP acceptance and paired foreign origin reachability are independent diagnostics, not a verified tunnel round trip.'}
