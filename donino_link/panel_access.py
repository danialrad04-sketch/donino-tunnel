"""Operator-only access configuration. Web API cannot alter listener/auth policy."""
import json
import tempfile
from pathlib import Path
from .config import atomic_json,endpoint,load_config,loopback


def configure_panel(path,listen,http=False,cert=None,key=None,public_host=None):
    path=Path(path).resolve()
    config=load_config(path)
    if 'panel' not in config:raise ValueError('install the role panel before changing its listener')
    endpoint(listen)
    if not http and not (cert and key) and not loopback(listen):
        raise ValueError('choose --http explicitly or provide both --cert and --key')
    if http and (cert or key):
        raise ValueError('--http cannot be combined with TLS files')
    if bool(cert)!=bool(key):
        raise ValueError('provide both --cert and --key')
    port=endpoint(listen)[1]
    occupied=[s['listen'] for s in config.get('services',[]) if s.get('protocol','tcp')=='tcp']
    if config['role']=='foreign':occupied.extend([config['health_listen'],*config.get('targets',{}).values()])
    if config['role']=='foreign':occupied.extend(r['listen'] for r in config.get('udp_relays',{}).values())
    for item in config.get('paths',[]):
        occupied.extend([item['health'],*item['backends'].values()])
    if port in [endpoint(address)[1] for address in occupied]:
        raise ValueError('panel port conflicts with a gateway service or backend')
    scheme='http' if http or not cert else 'https'
    host=public_host or endpoint(listen)[0]
    if ':' in host and not host.startswith('['):host='['+host+']'
    endpoint(f'{host}:{port}')
    url=None if host in ('0.0.0.0','[::]') else f'{scheme}://{host}'+('' if (scheme,port) in [('http',80),('https',443)] else f':{port}')
    panel=config['panel']
    panel.update(listen=listen,allow_insecure_http=http)
    if cert:
        panel.update(tls_cert=str(Path(cert).resolve()),tls_key=str(Path(key).resolve()))
        if not Path(panel['tls_cert']).is_file() or not Path(panel['tls_key']).is_file():
            raise ValueError('TLS files do not exist')
    else:
        panel.pop('tls_cert',None);panel.pop('tls_key',None)
    # Validate the complete future configuration before touching the live file.
    with tempfile.TemporaryDirectory(prefix='donino-panel-access-') as tmp:
        candidate=Path(tmp)/'node.json';atomic_json(candidate,config);load_config(candidate)
    backup=path.with_name(path.name+'.panel-backup')
    atomic_json(backup,json.loads(path.read_text()))
    atomic_json(path,config,preserve_permissions=True)
    return {'listen':listen,'url':url,'http':scheme=='http','backup':str(backup),'restart_required':True}
