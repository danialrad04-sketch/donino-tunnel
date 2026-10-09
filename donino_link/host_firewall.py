"""Opt-in active UFW integration, using a unique application profile per release.

Never enables/disables UFW, changes defaults, or deletes an unrelated rule.
Unsupported/inactive firewalls are reported for operator configuration.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from .config import atomic_json


def ports_spec(ports):
    if set(ports) != {'tcp','udp'}: raise ValueError('invalid firewall port map')
    values=[]
    for protocol in ['tcp','udp']:
        if not isinstance(ports[protocol],list) or any(isinstance(p,bool) or not isinstance(p,int) or not 1<=p<=65535 for p in ports[protocol]): raise ValueError('invalid firewall port')
        if ports[protocol]:values.append(','.join(str(p) for p in sorted(set(ports[protocol])))+'/'+protocol)
    return '|'.join(values)


def command(*args):
    result=subprocess.run(['ufw',*args],capture_output=True,text=True,timeout=30,env={**os.environ,'LC_ALL':'C'})
    if result.returncode: raise RuntimeError('UFW operation failed; inspect the private installer log')
    return result.stdout


def apply(node, release, tag, profile_dir=Path('/etc/ufw/applications.d')):
    if not re.fullmatch(r'[A-Za-z0-9-]{8,80}',tag):raise ValueError('invalid release tag')
    install=json.loads((Path(node)/'install.json').read_text())
    ports=install.get('public_ports',{'tcp':[],'udp':[]});spec=ports_spec(ports)
    ledger=Path(release)/'host-firewall.json'
    if not install.get('open_ufw'):return {'mode':'manual','changed':False}
    if not shutil.which('ufw') or not command('status').startswith('Status: active'):
        result={'mode':'manual','changed':False,'reason':'UFW absent or inactive; other host/provider policies must be configured separately'}
        atomic_json(ledger,result);return result
    if not spec:return {'mode':'ufw','changed':False}
    # Unique app identity avoids deleting another allow rule with identical ports.
    app='Donino-'+tag
    profile=Path(profile_dir)/app
    result={'mode':'ufw','changed':True,'app':app,'ports':ports}
    atomic_json(ledger,result)  # Intent is persisted before the first side effect.
    profile.write_text(f'[{app}]\ntitle=Donino managed tunnel ports\ndescription=Scoped ports for this Donino release\nports={spec}\n');profile.chmod(0o600)
    command('allow',app,'comment',app)
    return result


def remove(release, profile_dir=Path('/etc/ufw/applications.d')):
    ledger=Path(release)/'host-firewall.json'
    if not ledger.exists():return
    data=json.loads(ledger.read_text())
    app=data.get('app')
    if not app:return
    if not re.fullmatch(r'Donino-[A-Za-z0-9-]{8,80}',app):raise ValueError('invalid owned firewall profile')
    if shutil.which('ufw'):
        # 'show added' includes inactive stored rules as well as active ones.
        added=command('show','added')
        if re.search(r'\bufw allow [\'\"]?'+re.escape(app)+r'([\'\"]?\s|$)',added):
            command('--force','delete','allow',app)
    (Path(profile_dir)/app).unlink(missing_ok=True)
    atomic_json(ledger,{'mode':'ufw','changed':False,'removed':True})


def retire_previous(release):
    previous=(Path(release)/'previous-release').read_text().strip()
    if previous:
        path=Path(previous)
        if path.parent!=Path('/opt/donino-link/releases'):raise ValueError('invalid preceding release')
        remove(path)


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=['apply','remove','retire-previous']);parser.add_argument('--node');parser.add_argument('--release',required=True);parser.add_argument('--tag')
    args=parser.parse_args()
    if os.geteuid()!=0:parser.exit(1,'root required\n')
    try:
        if args.action=='apply':print(json.dumps(apply(args.node,args.release,args.tag)))
        elif args.action=='remove':remove(args.release)
        else:retire_previous(args.release)
    except (ValueError,RuntimeError,OSError) as error:parser.exit(1,str(error)+'\n')
