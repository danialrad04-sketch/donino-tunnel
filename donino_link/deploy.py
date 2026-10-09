import json
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
import uuid
from pathlib import Path


def build_payload(node, destination):
    package=Path(__file__).resolve().parent
    destination=Path(destination)
    destination.mkdir()
    shutil.copytree(package,destination/'donino_link',ignore=shutil.ignore_patterns('__pycache__'))
    shutil.copy2(package/'resources/pyproject.toml',destination/'pyproject.toml')
    (destination/'scripts').mkdir()
    for name in ['install-node.sh','rollback.sh']:
        shutil.copy2(package/'resources'/name,destination/'scripts'/name)
    shutil.copytree(node,destination/'node')


def ssh_args(host, identity=None):
    if not re.fullmatch(r'[a-z_][a-z0-9_-]*@(?:[a-zA-Z0-9_.-]+|\[[0-9a-fA-F:]+\])',host):
        raise ValueError('SSH host must be user@host (literal IPv6 in brackets)')
    args=['ssh','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=10','-o','ServerAliveInterval=15','-o','ServerAliveCountMax=2']
    if identity:
        args+=['-i',str(Path(identity).resolve())]
    return args+[host]


def deploy(plan, iran_host, foreign_host, identity=None, dry_run=False):
    plan=Path(plan).resolve()
    summary=json.loads((plan/'plan.json').read_text())
    hosts={'iran':iran_host,'foreign':foreign_host}
    for host in hosts.values():
        ssh_args(host,identity)
    if dry_run:
        return {'order':['foreign','iran'],'hosts':hosts,'transports':summary['transports'],
                'host_key_verification':'strict','firewall_changes':'Paqet tagged rules only; provider firewall must be opened separately',
                'remote_root_required':True,'remote_smoke_test':'authenticated end-to-end probes; require at least one working path'}
    # Preflight both servers before uploading or changing either one.
    for host in hosts.values():
        subprocess.run(ssh_args(host,identity)+['test "$(id -u)" -eq 0 && command -v python3 && command -v systemctl && test -d /run/systemd/system'],check=True)
    installed=[]
    try:
        for role in ['foreign','iran']:
            host=hosts[role]
            nonce=uuid.uuid4().hex
            remote=f'/var/tmp/donino-link-{nonce}'
            with tempfile.TemporaryDirectory(prefix='donino-deploy-') as tmp:
                stage=Path(tmp)/'payload'
                build_payload(plan/role,stage)
                # Each node receives only its own private keys, never CA signing key or the other node's bundle.
                archive=Path(tmp)/'payload.tar.gz'
                with tarfile.open(archive,'w:gz') as tar:
                    for item in stage.iterdir():
                        tar.add(item,arcname=item.name)
                subprocess.run(ssh_args(host,identity)+[f'mkdir -m 700 {remote}'],check=True)
                try:
                    with archive.open('rb') as f:
                        subprocess.run(ssh_args(host,identity)+[f'tar -xzf - -C {remote}'],stdin=f,check=True)
                    subprocess.run(ssh_args(host,identity)+[f'bash {remote}/scripts/install-node.sh {remote}'],check=True)
                    installed.append(host)
                finally:
                    subprocess.run(ssh_args(host,identity)+[f'rm -rf -- {remote}'],check=False)
        rows=[]
        for _ in range(15):
            check=subprocess.run(ssh_args(iran_host,identity)+['/opt/donino-link/current/venv/bin/donino-link doctor --config /etc/donino-link/current/node.json'],capture_output=True,text=True)
            try:
                rows=json.loads(check.stdout)
            except ValueError:
                rows=[]
            if any(r['ok'] for r in rows):
                break
            time.sleep(2)
        else:
            raise RuntimeError('no authenticated end-to-end path became healthy; rolled back both nodes. Check provider firewall and plan.json ports.')
    except BaseException:
        for host in reversed(installed):
            subprocess.run(ssh_args(host,identity)+['bash /opt/donino-link/current/scripts/rollback.sh'],check=False)
        raise
    return {'installed':hosts,'panel':'ssh -L 8090:127.0.0.1:8090 '+iran_host,'firewall':summary['firewall'],
            'probes':rows,'degraded':any(not r['ok'] for r in rows),
            'origin_services_available':all(all(r.get('services',{}).values()) for r in rows if r['ok'])}
