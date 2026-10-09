"""Offline two-node plan generation. Plans contain secrets and must stay private."""
import ipaddress
import json
import re
import secrets
import shutil
import subprocess
from pathlib import Path
from .config import atomic_json, endpoint
from .panel import password_record

ETC = "/etc/donino-link/current"
OPT = "/opt/donino-link/current"
TRANSPORTS = ("frp-wss", "frp-quic", "backpack-wss", "paqet", "backhaul-wss")
EXPERIMENTAL = {"backpack-wss", "paqet", "backhaul-wss"}


def q(v):
    return json.dumps(v)


def write(path, text, mode=0o600):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(text)
    path.chmod(mode)


def unit(name, command, raw=False):
    capabilities = "CAP_NET_RAW CAP_NET_ADMIN" if raw else "CAP_NET_BIND_SERVICE"
    families = "AF_INET AF_INET6 AF_UNIX AF_NETLINK AF_PACKET" if raw else "AF_INET AF_INET6 AF_UNIX"
    return f"""[Unit]
Description=Donino Link {name}
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=120
StartLimitBurst=15

[Service]
Type=simple
User=donino-link
Group=donino-link
ExecStart={command}
Restart=on-failure
RestartSec=5
TimeoutStopSec=20
KillMode=control-group
LimitNOFILE=65536
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/donino-link
AmbientCapabilities={capabilities}
CapabilityBoundingSet={capabilities}
RestrictAddressFamilies={families}
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
TasksMax=512
MemoryMax=768M

[Install]
WantedBy=multi-user.target
"""


def make_certs(directory, iran, renew=False):
    directory.mkdir(parents=True,exist_ok=True)
    def run(*args):
        subprocess.run(["openssl",*args],cwd=directory,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    if renew:
        if not (directory/'ca.key').exists() or not (directory/'ca.crt').exists():
            raise ValueError('renewal requires the original offline CA key and certificate')
        run('x509','-in','ca.crt','-checkend',str(91*86400),'-noout')
    else:
        run("req","-x509","-newkey","rsa:3072","-nodes","-days","365","-keyout","ca.key","-out","ca.crt","-subj","/CN=Donino Link private CA","-addext","basicConstraints=critical,CA:TRUE","-addext","keyUsage=critical,keyCertSign,cRLSign")
    try:
        ipaddress.ip_address(iran)
        san = "IP:"+iran
    except ValueError:
        san = "DNS:"+iran
    for who,purpose in [("server","serverAuth"),("client","clientAuth")]:
        run("req","-newkey","rsa:3072","-nodes","-keyout",who+".key","-out",who+".csr","-subj","/CN=donino-"+who)
        extra = "\nsubjectAltName="+san if who == "server" else ""
        write(directory/(who+".ext"),"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage="+purpose+extra+"\n")
        run("x509","-req","-in",who+".csr","-CA","ca.crt","-CAkey","ca.key","-CAcreateserial","-out",who+".crt","-days","90","-extfile",who+".ext")
    for path in directory.iterdir():
        path.chmod(0o600)


def renew_plan(output):
    output=Path(output)
    summary=json.loads((output/'plan.json').read_text())
    make_certs(output/'ca',summary['iran'],renew=True)
    for role,who in [('iran','server'),('foreign','client')]:
        for suffix in ['crt','key']:
            shutil.copy2(output/'ca'/f'{who}.{suffix}',output/role/'certs'/f'{who}.{suffix}')


def frp_config(role, transport, iran, port, token, mappings):
    tls = f'{ETC}/certs/'
    if role == "iran":
        lines = ['bindAddr = "0.0.0.0"',f'bindPort = {port}', 'proxyBindAddr = "127.0.0.1"',
                 f'auth.token = {q(token)}','auth.additionalScopes = ["HeartBeats", "NewWorkConns"]',
                 'transport.tls.force = true',f'transport.tls.certFile = {q(tls+"server.crt")}',
                 f'transport.tls.keyFile = {q(tls+"server.key")}',f'transport.tls.trustedCaFile = {q(tls+"ca.crt")}',
                 'log.to = "console"','log.level = "warn"',
                 'allowPorts = ['+','.join('{single = '+str(local)+'}' for _,local,_ in mappings)+']']
        if transport == "frp-quic":
            lines.append(f'quicBindPort = {port}')
        else:
            # Outer mTLS terminates in our dedicated front; frps receives only
            # loopback WebSocket. Never expose this non-TLS internal listener.
            lines[0] = 'bindAddr = "127.0.0.1"'
            lines[1] = f'bindPort = {port+1000}'
            lines[5] = 'transport.tls.force = false'
            # frps automatically forces inner TLS whenever trustedCaFile is set.
            # mTLS is already required by the public front, so no inner CA here.
            lines = [line for line in lines if not line.startswith('transport.tls.trustedCaFile')]
    else:
        lines = [f'serverAddr = {q(iran)}',f'serverPort = {port}',f'auth.token = {q(token)}',
                 'auth.additionalScopes = ["HeartBeats", "NewWorkConns"]','loginFailExit = false',
                 f'transport.protocol = {q("quic" if transport == "frp-quic" else "wss")}',
                 'transport.tls.enable = true','transport.tls.disableCustomTLSFirstByte = true',
                 f'transport.tls.serverName = {q(iran)}',f'transport.tls.certFile = {q(tls+"client.crt")}',
                 f'transport.tls.keyFile = {q(tls+"client.key")}',f'transport.tls.trustedCaFile = {q(tls+"ca.crt")}',
                 'transport.poolCount = 4','transport.tcpMuxKeepaliveInterval = 10','log.to = "console"','log.level = "warn"']
        for name,local,target in mappings:
            host,target_port = endpoint(target)
            lines += ['\n[[proxies]]',f'name = {q(name)}','type = "tcp"',f'localIP = {q(host)}',f'localPort = {target_port}',f'remotePort = {local}']
    return "\n".join(lines)+"\n"


def reverse_config(role, engine, iran, port, token, mappings):
    lines = ['['+('server' if role=="iran" else 'client')+']', 'transport = "wss"',f'token = {q(token)}',
             'nodelay = true','keepalive_period = 30','sniffer = false','web_port = 0','log_level = "warn"']
    if engine == "backpack":
        lines += ['skip_optz = true','simple_auth = false','accept_udp = false'] if role == "iran" else ['skip_optz = true','simple_auth = false']
    if role == "iran":
        lines += [f'bind_addr = "0.0.0.0:{port}"',f'tls_cert = "{ETC}/certs/server.crt"',f'tls_key = "{ETC}/certs/server.key"',
                  'ports = ['+','.join(q(f"127.0.0.1:{local}={target}") for _,local,target in mappings)+']']
    else:
        host = f'[{iran}]' if ':' in iran else iran
        lines += [f'remote_addr = {q(host+":"+str(port))}','connection_pool = 4','retry_interval = 3','dial_timeout = 5']
    return "\n".join(lines)+"\n"


def paqet_config(role, iran, foreign, port, token, mappings):
    # JSON is a YAML subset; generated file is accepted by Paqet's YAML parser.
    host = iran if role == "iran" else foreign
    config = {"role":"client" if role=="iran" else "server","log":{"level":"warn"},
              "network":{"interface":"AUTO","ipv4":{"addr":host+":"+str(0 if role=="iran" else port),"router_mac":"AUTO"}},
              "transport":{"protocol":"kcp","conn":2,"kcp":{"mode":"normal","mtu":1150,"block":"aes-128-gcm","key":token}}}
    if role == "iran":
        config["server"] = {"addr":foreign+":"+str(port)}
        config["forward"] = [{"listen":f"127.0.0.1:{local}","target":target,"protocol":"tcp"} for _,local,target in mappings]
    else:
        config["listen"] = {"addr":":"+str(port)}
    return json.dumps(config,indent=2)+"\n"


def make_plan(output, iran, foreign, services, transports, password, experimental=False, base=30000, carrier_base=24443, health_port=19090, paqet_port=33434):
    if not transports or len(set(transports)) != len(transports) or not set(transports) <= set(TRANSPORTS):
        raise ValueError("select unique supported transports")
    if set(transports) & EXPERIMENTAL and not experimental:
        raise ValueError("BackPack, Paqet and legacy Backhaul need --experimental; read docs/research.md first")
    endpoint(iran+":443" if ':' not in iran else '['+iran+']:443')
    endpoint(foreign+":443" if ':' not in foreign else '['+foreign+']:443')
    if "paqet" in transports:
        for host in [iran,foreign]:
            if ipaddress.ip_address(host).version != 4:
                raise ValueError("automatic Paqet setup needs literal public IPv4 addresses")
        if paqet_port < 1024 or paqet_port in (8080,8443,19090) or not paqet_port <= 65535:
            raise ValueError("Paqet needs a dedicated non-standard high port")
    if not services or len(services)>40:
        raise ValueError("use between 1 and 40 TCP services")
    ids=set()
    for service in services:
        if service['id'] in ids or not re.fullmatch(r"[a-z][a-z0-9-]{0,31}",service['id']):
            raise ValueError("invalid/duplicate service name")
        ids.add(service['id'])
        endpoint(service['listen'])
        if not ipaddress.ip_address(endpoint(service['target'])[0]).is_loopback:
            raise ValueError("remote targets must be literal loopback addresses")
    ports = [endpoint(s['listen'])[1] for s in services]+[health_port,8090]
    for i,t in enumerate(transports):
        ports.extend([base+i*100+j for j in range(len(services))]+[base+i*100+50,paqet_port if t=='paqet' else carrier_base+i])
        if t=='frp-wss':
            ports.append(carrier_base+i+1000)
    if len(ports)!=len(set(ports)) or any(p<1 or p>65535 for p in ports):
        raise ValueError("port ranges overlap or are out of bounds; choose different bases")
    output = Path(output)
    if output.exists():
        raise ValueError("plan output already exists; use a new private directory")
    output.mkdir(mode=0o700,parents=True)
    health_key = secrets.token_hex(32)
    (output/"ca").mkdir(mode=0o700)
    make_certs(output/"ca",iran)
    paths,engines,units = [],set(),{"iran":[],"foreign":[]}
    for role in ['iran','foreign']:
        root = output/role
        (root/"certs").mkdir(parents=True,mode=0o700)
        for name in ['ca.crt']+(['server.crt','server.key'] if role=='iran' else ['client.crt','client.key']):
            shutil.copy2(output/"ca"/name,root/"certs"/name)
        filename='node.json'
        command=f'{OPT}/venv/bin/python -m donino_link.cli run --config {ETC}/{filename}'
        write(root/'units'/'donino-link.service',unit('gateway' if role=='iran' else 'health responder',command))
        units[role].append('donino-link.service')
    for i,t in enumerate(transports):
        engine=t.split('-')[0]
        if engine=='frp':
            engine='frp'
        engines.add(engine)
        local_base=base+i*100
        mappings=[(s['id'],local_base+j,s['target']) for j,s in enumerate(services)]+[('health',local_base+50,f'127.0.0.1:{health_port}')]
        paths.append({'id':t,'transport':t,'priority':10+i*10,'health':f'127.0.0.1:{local_base+50}',
                      'backends':{s['id']:f'127.0.0.1:{local_base+j}' for j,s in enumerate(services)}})
        token=secrets.token_hex(32)
        port=paqet_port if t=='paqet' else carrier_base+i
        for role in ['iran','foreign']:
            root=output/role
            ext='yaml' if t=='paqet' else 'toml'
            file=f'transports/{t}.{ext}'
            if t.startswith('frp'):
                text=frp_config(role,t,iran,port,token,mappings)
                binary='frps' if role=='iran' else 'frpc'
                command=f'{OPT}/bin/{binary} -c {ETC}/{file}'
            elif t=='paqet':
                text=paqet_config(role,iran,foreign,port,token,mappings)
                command=f'{OPT}/bin/paqet run -c {ETC}/{file}'
            else:
                text=reverse_config(role,engine,iran,port,token,mappings)
                command=f'{OPT}/bin/{engine} -c {ETC}/{file}'
            write(root/file,text)
            text=unit(t,command,raw=t=='paqet')
            if t=='paqet' and role=='foreign':
                text=text.replace('After=network-online.target','After=network-online.target donino-link-raw.service\nRequires=donino-link-raw.service')
                raw=f'''[Unit]
Description=Donino Link scoped Paqet rules
After=network-online.target
[Service]
Type=oneshot
RemainAfterExit=true
ExecStart={OPT}/venv/bin/python -m donino_link.raw_rules apply --peer {iran} --port {port}
ExecStop={OPT}/venv/bin/python -m donino_link.raw_rules remove --peer {iran} --port {port}
[Install]
WantedBy=multi-user.target
'''
                write(root/'units'/'donino-link-raw.service',raw)
                units[role].insert(0,'donino-link-raw.service')
            name=f'donino-link-{t}.service'
            write(root/'units'/name,text)
            units[role].append(name)
            if t=='frp-wss' and role=='iran':
                front_name='donino-link-frp-wss-front.service'
                front_command=f'{OPT}/venv/bin/python -m donino_link.tlsfront --listen 0.0.0.0:{port} --upstream 127.0.0.1:{port+1000} --cert {ETC}/certs/server.crt --key {ETC}/certs/server.key --ca {ETC}/certs/ca.crt'
                front_unit=unit('FRP WSS mutual TLS front',front_command)
                front_unit=front_unit.replace('After=network-online.target',f'After=network-online.target {name}\nRequires={name}')
                write(root/'units'/front_name,front_unit)
                units[role].append(front_name)
    atomic_json(output/'iran'/'node.json',{'schema':1,'role':'iran','health_key':health_key,'services':[{k:s[k] for k in ['id','listen']} for s in services],
                'paths':paths,'policy':{'probe_interval':3,'probe_timeout':2,'failures':3,'recoveries':2,'connect_timeout':2,'idle_timeout':300,'max_connections':2048},
                'panel':{'listen':'127.0.0.1:8090','credentials_file':f'{ETC}/admin.json','api_token_file':f'{ETC}/api-token'},'state_db':'/var/lib/donino-link/state.sqlite3'})
    atomic_json(output/'foreign'/'node.json',{'schema':1,'role':'foreign','health_key':health_key,'health_listen':f'127.0.0.1:{health_port}',
                'targets':{s['id']:s['target'] for s in services}})
    atomic_json(output/'iran'/'admin.json',password_record(password))
    write(output/'iran'/'api-token',secrets.token_urlsafe(48)+'\n')
    for role in ['iran','foreign']:
        atomic_json(output/role/'install.json',{'schema':1,'role':role,'engines':sorted(engines),'units':units[role],
                    'paqet_peer':foreign if role=='iran' else iran,'paqet_port':paqet_port if 'paqet' in transports else None})
    summary={'schema':1,'iran':iran,'foreign':foreign,'transports':transports,'services':services,'units':units,'experimental':experimental,
             'certificate_days':90,'firewall':{'iran':{'tcp':[carrier_base+i for i,t in enumerate(transports) if t!='paqet']+[endpoint(s['listen'])[1] for s in services],
                                  'udp':[carrier_base+i for i,t in enumerate(transports) if t=='frp-quic']},
                                  'foreign':{'tcp':[paqet_port] if 'paqet' in transports else [],'udp':[]}}}
    atomic_json(output/'plan.json',summary)
    return summary
