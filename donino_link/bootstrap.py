"""Role-specific terminal installation without an already configured tunnel."""
import json
import os
import secrets
import shutil
import subprocess
import tempfile
from pathlib import Path
from .config import atomic_json, endpoint, load_config
from .deploy import build_payload
from .panel import password_record
from .plan import unit, write
from .provision import public_address, integer, LIVE, read_json


def stable_auth(role, password=None, old_panel=None):
    import grp
    root=Path('/var/lib/donino-link');root.mkdir(mode=0o700,exist_ok=True)
    paths={'credentials_file':root/(role+'-admin.json'),'api_token_file':root/(role+'-api-token')}
    gid=grp.getgrnam('donino-link').gr_gid
    for field,path in paths.items():
        if not path.exists():
            if old_panel:
                shutil.copyfile(old_panel[field],path)
            elif field=='credentials_file':atomic_json(path,password_record(password))
            else:path.write_text(secrets.token_urlsafe(48)+'\n')
        os.chown(path,0,gid);path.chmod(0o640)
    return {k:str(v) for k,v in paths.items()}


def preserve_foreign_panel(node):
    """SSH deployments retain the foreign panel independently of tunnel bundles."""
    node=Path(node);cfg=read_json(node/'node.json');install=read_json(node/'install.json')
    if cfg['role']!='foreign' or 'panel' in cfg or not LIVE.exists():return
    previous=load_config(LIVE)
    if 'panel' not in previous:return
    panel=dict(previous['panel']);panel.update(stable_auth('foreign',old_panel=panel))
    # Move an existing optional panel TLS chain out of versioned release paths.
    for field in ['tls_cert','tls_key']:
        if panel.get(field):
            destination=Path('/var/lib/donino-link')/('foreign-'+field+'.pem')
            if str(Path(panel[field]).resolve())!=str(destination):shutil.copyfile(panel[field],destination)
            import grp
            os.chown(destination,0,grp.getgrnam('donino-link').gr_gid);destination.chmod(0o640)
            panel[field]=str(destination)
    cfg['panel']=panel;cfg['state_db']='/var/lib/donino-link/foreign-state.sqlite3'
    if previous.get('public_address'):cfg['public_address']=previous['public_address']
    port=endpoint(panel['listen'])[1]
    planned={p['port'] for p in install.get('listeners',[])}
    targets={endpoint(t)[1] for t in cfg.get('targets',{}).values()}
    if port in planned or port in targets:raise ValueError('foreign panel port conflicts with a tunnel listener or origin')
    install.setdefault('listeners',[]).append({'protocol':'tcp','port':port})
    install.setdefault('public_ports',{}).setdefault('tcp',[]).append(port)
    agent=read_json('/etc/donino-foreign-agent.json',{})
    if agent:
        if agent['port'] in planned or agent['port'] in targets or agent['port']==port:raise ValueError('foreign pairing port conflicts with a tunnel or panel')
        install['public_ports']['tcp'].append(agent['port'])
        # The agent is independent of Donino tunnel units, so its occupied port
        # is not part of the replacing tunnel listener preflight.
    atomic_json(node/'node.json',cfg);atomic_json(node/'install.json',install)


def make_bootstrap(directory,role,address,password,panel_port=None,agent_port=9444,open_ufw=True):
    if role not in ('iran','foreign'):raise ValueError('select iran or foreign')
    address=public_address(address);port=integer(panel_port if panel_port is not None else (8090 if role=='iran' else 8091),1024,65535,'panel port')
    agent_port=integer(agent_port,1024,65535,'agent port')
    if role=='foreign' and (port in (agent_port,19090) or agent_port==19090):raise ValueError('panel, pairing and health ports must differ')
    password_record(password)  # Validate before touching managed authentication.
    node=Path(directory);node.mkdir(parents=True,mode=0o700)
    listen_host='[::]' if ':' in address else '0.0.0.0'
    panel={'listen':f'{listen_host}:{port}','allow_insecure_http':True,**stable_auth(role,password)}
    cfg={'schema':1,'role':role,'health_key':secrets.token_hex(32),'bootstrap':True,'public_address':address,
         'panel':panel,'state_db':'/var/lib/donino-link/'+('state.sqlite3' if role=='iran' else 'foreign-state.sqlite3')}
    if role=='iran':cfg.update(services=[],paths=[])
    else:cfg.update(health_listen='127.0.0.1:19090',targets={})
    atomic_json(node/'node.json',cfg)
    write(node/'units'/'donino-link.service',unit('Iran control panel' if role=='iran' else 'foreign monitoring panel',
          '/opt/donino-link/current/venv/bin/python -m donino_link.cli run --config /etc/donino-link/current/node.json'))
    listeners=[{'protocol':'tcp','port':port}]
    if role=='foreign':listeners.append({'protocol':'tcp','port':19090})
    atomic_json(node/'install.json',{'schema':1,'role':role,'engines':[],'units':['donino-link.service'],
                'browser':False,'paqet_port':None,'paqet_peer':address,'public_ports':{'tcp':[port]+([agent_port] if role=='foreign' else []),'udp':[]},
                'listeners':listeners,'open_ufw':open_ufw})
    load_config(node/'node.json')
    return cfg


def install(role,address,password=None,panel_port=None,agent_port=9444,open_ufw=True,allow_private=False,upgrade=False):
    if os.geteuid()!=0:raise ValueError('run setup as root on the target server')
    if role not in ('iran','foreign'):raise ValueError('select iran or foreign')
    public_address(address)
    existing=load_config(LIVE) if LIVE.exists() else None
    if role=='foreign':agent_port=read_json('/etc/donino-foreign-agent.json',{}).get('port',agent_port)
    if existing and existing['role']!=role:raise ValueError('this node already has the other role; do not replace it')
    if existing and not upgrade:raise ValueError('Donino is already installed; use --upgrade to preserve its configuration')
    if existing:
        for directory in ('/var/lib/donino-control','/var/lib/donino-foreign'):
            if (Path(directory)/'import-edit.json').exists():raise ValueError('finish or recover the detected-service configuration edit before upgrading')
        for p in Path('/var/lib/donino-control/jobs').glob('*/job.json'):
            if read_json(p).get('status')=='running':raise ValueError('finish the current installation job before upgrading')
        if read_json('/var/lib/donino-foreign/lease.json',{}).get('expires',0)>__import__('time').time():raise ValueError('foreign node has an active installation lease')
        if any(row['status']=='running' for row in read_json('/var/lib/donino-foreign/actions.json',[])):raise ValueError('finish the current foreign service operation before upgrading')
    subprocess.run(['id','donino-link'],capture_output=True).returncode==0 or subprocess.run(['useradd','--system','--user-group','--home','/var/lib/donino-link','--shell','/usr/sbin/nologin','donino-link'],check=True)
    import grp
    state=Path('/var/lib/donino-link');state.mkdir(mode=0o700,exist_ok=True)
    os.chown(state,__import__('pwd').getpwnam('donino-link').pw_uid,grp.getgrnam('donino-link').gr_gid)
    with tempfile.TemporaryDirectory(prefix='donino-node-') as tmp:
        node=Path(tmp)/'node'
        if existing:
            shutil.copytree(LIVE.parent,node)
            if 'panel' not in existing:
                fresh=make_bootstrap(Path(tmp)/'panel',role,address,password,panel_port,agent_port,open_ufw)
                existing.update(panel=fresh['panel'],state_db=fresh['state_db']);atomic_json(node/'node.json',existing)
                manifest=read_json(node/'install.json');port=endpoint(fresh['panel']['listen'])[1]
                occupied={p['port'] for p in manifest.get('listeners',[])}|{endpoint(t)[1] for t in existing.get('targets',{}).values()}
                actual_agent=read_json('/etc/donino-foreign-agent.json',{}).get('port',agent_port)
                if port in occupied or (role=='foreign' and actual_agent in occupied):raise ValueError('new panel or agent conflicts with a tunnel listener or origin')
                manifest.setdefault('listeners',[]).append({'protocol':'tcp','port':port})
                manifest.setdefault('public_ports',{}).setdefault('tcp',[]).extend([port]+([actual_agent] if role=='foreign' else []))
                atomic_json(node/'install.json',manifest)
        else:make_bootstrap(node,role,address,password,panel_port,agent_port,open_ufw)
        if role=='foreign':
            from .peer import initialize
            if not Path('/etc/donino-foreign-agent.json').exists():initialize(agent_port)
        payload=Path(tmp)/'payload';build_payload(node,payload)
        if allow_private:atomic_json('/etc/donino-control.json',{'allow_private_peers':True})
        subprocess.run(['bash',str(payload/'scripts/install-node.sh'),str(payload)],check=True)
    if existing:
        service='donino-control.service' if role=='iran' else 'donino-foreign-agent.service'
        subprocess.run(['systemctl','restart',service],check=True)
    cfg=load_config(LIVE);host=address if ':' not in address else '['+address+']'
    return {'role':role,'panel':f'http://{host}:{endpoint(cfg["panel"]["listen"])[1]}','paired':False,
            'next':'Open the foreign panel, generate a pairing code, then enter it in the Iran panel.'}


if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser();p.add_argument('--preserve',required=True)
    try:preserve_foreign_panel(p.parse_args().preserve)
    except (OSError,ValueError,KeyError) as error:p.exit(1,str(error)+'\n')
