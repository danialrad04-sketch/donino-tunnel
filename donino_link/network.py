"""Resolve the actual egress interface and gateway MAC on each node."""
import ipaddress
import json
import re
import subprocess
from pathlib import Path
from .config import atomic_json


def command_json(*args):
    return json.loads(subprocess.check_output(args,text=True,timeout=10))


def discover(peer):
    ipaddress.IPv4Address(peer)
    routes=command_json('ip','-j','route','get',peer)
    if not routes or 'dev' not in routes[0] or 'prefsrc' not in routes[0]:
        raise ValueError('cannot find a usable IPv4 egress route')
    route=routes[0]
    if not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,32}',route['dev']):
        raise ValueError('invalid interface name')
    gateway=route.get('gateway',peer)
    def neighbour():
        neighbours=command_json('ip','-j','neigh','show','to',gateway,'dev',route['dev'])
        return next((n['lladdr'] for n in neighbours if re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}',n.get('lladdr',''))),None)
    mac=neighbour()
    if not mac:
        subprocess.run(['ping','-c','1','-W','1',gateway],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=3)
        mac=neighbour()
    if not mac:
        raise ValueError('gateway MAC unresolved; verify the route and neighbour table before installing Paqet')
    return route['dev'],route['prefsrc'],mac


def prepare_paqet(node):
    node=Path(node)
    metadata=json.loads((node/'install.json').read_text())
    if not metadata.get('paqet_port'):
        return
    interface,local_ip,mac=discover(metadata['paqet_peer'])
    path=node/'transports'/'paqet.yaml'
    config=json.loads(path.read_text())
    port=0 if metadata['role']=='iran' else metadata['paqet_port']
    config['network']={'interface':interface,'ipv4':{'addr':f'{local_ip}:{port}','router_mac':mac}}
    atomic_json(path,config)
