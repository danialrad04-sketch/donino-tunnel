"""Read-only engine adapters. Detection never executes a vendor installer."""
import re
from pathlib import Path

# Formats and observability are explicit; unsupported vendor schemas stay read-only.
ADAPTERS = {
    'paqet': {'name': 'Paqet', 'protocol': 'KCP / raw TCP', 'formats': ['yaml', 'json'], 'edit': True, 'probe': 'paired-socks-or-forward-diagnostics'},
    'frp': {'name': 'FRP', 'protocol': 'TCP / WSS / QUIC', 'formats': ['toml', 'json', 'yaml'], 'edit': False, 'probe': 'configured-endpoints'},
    'backpack': {'name': 'BackPack', 'protocol': 'vendor transport', 'formats': ['toml', 'json', 'yaml'], 'edit': False, 'probe': 'configured-endpoints'},
    'backhaul': {'name': 'Backhaul', 'protocol': 'vendor transport', 'formats': ['toml', 'json', 'yaml'], 'edit': False, 'probe': 'configured-endpoints'},
    'xray': {'name': 'Xray', 'protocol': 'application proxy', 'formats': ['json'], 'edit': False, 'probe': 'configured-endpoints'},
    'sing-box': {'name': 'sing-box', 'protocol': 'application proxy', 'formats': ['json'], 'edit': False, 'probe': 'configured-endpoints'},
    'wireguard': {'name': 'WireGuard', 'protocol': 'UDP', 'formats': ['conf'], 'edit': False, 'probe': 'interface-only'},
    'rathole': {'name': 'Rathole', 'protocol': 'TCP / Noise / TLS', 'formats': ['toml'], 'edit': False, 'probe': 'configured-endpoints'},
    'gost': {'name': 'GOST', 'protocol': 'vendor transport', 'formats': ['yaml', 'json'], 'edit': False, 'probe': 'configured-endpoints'},
    'chisel': {'name': 'Chisel', 'protocol': 'HTTP / WebSocket / SSH', 'formats': ['json'], 'edit': False, 'probe': 'process-only'},
    'browser-wss': {'name': 'BrowserLink', 'protocol': 'HTTPS / WebSocket', 'formats': ['json'], 'edit': False, 'probe': 'donino-signed'},
    'donino-mux': {'name': 'Donino Mux', 'protocol': 'mTLS / WSS', 'formats': ['json'], 'edit': False, 'probe': 'donino-signed'},
    'donino-continuum': {'name': 'Donino Continuum', 'protocol': 'resumable mTLS / WSS', 'formats': ['json'], 'edit': False, 'probe': 'donino-signed'},
}


def identify(argv, unit=''):
    if not argv: return None
    name = Path(argv[0]).name.lower()
    if re.fullmatch(r'paqet(?:[_-](?:linux|amd64|arm64|x86_64|aarch64)[A-Za-z0-9_-]*)?', name): return 'paqet'
    for engine, names in [('frp', ('frpc', 'frps')), ('backpack', ('backpack',)), ('backhaul', ('backhaul',)),
                          ('xray', ('xray',)), ('wireguard', ('wg-quick',)), ('sing-box', ('sing-box',)),
                          ('rathole', ('rathole',)), ('gost', ('gost',)), ('chisel', ('chisel',))]:
        if name in names: return engine
    # Match module argv, not just the service's potentially misleading name.
    if name.startswith('python') and '-m' in argv:
        i = argv.index('-m')
        module = argv[i + 1] if i + 1 < len(argv) else ''
        return {'donino_link.browser': 'browser-wss', 'donino_link.mux': 'donino-mux',
                'donino_link.continuum': 'donino-continuum'}.get(module)
    return None


def capabilities(row):
    adapter = ADAPTERS.get(row['engine'], {})
    auxiliary = bool(re.search(r'(?:^|[-_.])(monitor|webui|dashboard|watchdog)(?:[-_.]|$)', row['unit']))
    service = row['engine'] in ADAPTERS and row.get('source') != 'process' and bool(row.get('descriptor') and row.get('binary'))
    return {**adapter, 'category': 'auxiliary' if auxiliary else 'proxy' if row['engine'] in ('xray', 'sing-box') else 'tunnel',
            'logs': row.get('source') != 'process', 'inspect': True, 'control': service,
            'edit': bool(adapter.get('edit') and row.get('editable') and not row.get('managed_by_donino')),
            'traffic': row['engine'] in ('browser-wss', 'donino-mux', 'donino-continuum'),
            'signed_probe': row['engine'] == 'paqet' and bool(row.get('config', {}).get('socks5')),
            'detection': 'process-argv' if row.get('pid') else 'systemd-exec'}


def paqet_overview(managed,inventory):
    instances=[r for r in inventory.get('services',[]) if r['engine']=='paqet']
    return {**managed,'managed_installation':bool(managed.get('installed')),
            'version':managed.get('version') if managed.get('installed') else None,
            'installed':bool(managed.get('installed') or instances),'instances':instances}
