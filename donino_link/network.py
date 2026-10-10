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
    family=ipaddress.ip_address(peer).version
    routes=command_json('ip','-j','route','get',peer)
    if not routes or 'dev' not in routes[0] or not routes[0].get('prefsrc',routes[0].get('src')):
        raise ValueError('cannot find a usable IP egress route')
    route=routes[0]
    if not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,15}',route['dev']):
        raise ValueError('invalid interface name')
    gateway=route.get('gateway',peer)
    def neighbour():
        neighbours=command_json('ip','-j','neigh','show','to',gateway,'dev',route['dev'])
        return next((n['lladdr'] for n in neighbours if re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}',n.get('lladdr',''))),None)
    mac=neighbour()
    if not mac:
        subprocess.run(['ping',('-6' if family==6 else '-4'),'-c','1','-W','1',gateway],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=3)
        mac=neighbour()
    if not mac:
        raise ValueError('gateway MAC unresolved; verify the route and neighbour table before installing Paqet')
    return route['dev'],route.get('prefsrc',route.get('src')),mac


def prepare_paqet(node):
    node=Path(node)
    metadata=json.loads((node/'install.json').read_text())
    if not metadata.get('paqet_port'):
        return
    settings=metadata.get('paqet_network',{})
    if not all(settings.get(k) for k in ('interface','local_ip','router_mac')):
        interface,local_ip,mac=discover(metadata['paqet_peer'])
    else:interface,local_ip,mac=settings['interface'],settings['local_ip'],settings['router_mac']
    interface=settings.get('interface',interface);local_ip=settings.get('local_ip',local_ip);mac=settings.get('router_mac',mac)
    family=ipaddress.ip_address(metadata['paqet_peer']).version
    if ipaddress.ip_address(local_ip).version!=family:raise ValueError('Paqet local IP and peer families differ')
    # A typed override must refer to an address really assigned to this NIC.
    if settings:
        assigned=command_json('ip','-j','addr','show','dev',interface)
        addresses={str(ipaddress.ip_address(a['local'])) for row in assigned for a in row.get('addr_info',[]) if 'local' in a}
        if str(ipaddress.ip_address(local_ip)) not in addresses or (settings.get('ipv6') and str(ipaddress.ip_address(settings['ipv6'])) not in addresses):raise ValueError('Paqet local address is not assigned to selected interface')
    path=node/'transports'/'paqet.yaml'
    config=json.loads(path.read_text())
    port=settings.get('source_port',0) if metadata['role']=='iran' else metadata['paqet_port']
    address=f'[{local_ip}]' if family==6 else local_ip
    config['network']['interface']=interface
    config['network']['ipv'+str(family)]={'addr':f'{address}:{port}','router_mac':mac}
    if settings.get('ipv6'):
        if family==6 and str(ipaddress.ip_address(settings['ipv6']))!=str(ipaddress.ip_address(local_ip)):raise ValueError('primary IPv6 and additional IPv6 must match for an IPv6 peer')
        config['network']['ipv6']={'addr':f"[{settings['ipv6']}]:{port}",'router_mac':settings['ipv6_router_mac']}
    atomic_json(path,config)
