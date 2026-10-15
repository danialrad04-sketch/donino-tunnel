"""Typed, isolated 3x-ui/Xray bootstrap. No vendor source or installer scripts.

The GPL upstream distribution is fetched unchanged, pinned by SHA256. Its
service and database are separate from existing x-ui/PasarGuard installations.
"""
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import tarfile
import tempfile
import threading
import urllib.request
from pathlib import Path
from .config import atomic_json

VERSION = 'v3.10.2'
PORT = 20539
UNIT = 'donino-vpn-backend.service'
CHECKSUMS = {'amd64': 'bfda7921984e7a72555c38d4e861c7a8b67b3686b658608937de99682f1452d0',
             'arm64': 'a867c65ce52ad49f6504dd4c9c395337dc92ba57ae478da4f1b7ddb624014ed5'}
INSTALL_LOCK = threading.Lock()
MAX_ARCHIVE = 128 * 1024 * 1024


def extract(archive, destination, arch):
    """No links, traversal, arbitrary paths or executable vendor shell scripts."""
    destination = Path(destination)
    allowed = {'x-ui/x-ui', 'x-ui/bin/xray-linux-'+arch, 'x-ui/bin/geoip.dat', 'x-ui/bin/geosite.dat',
               'x-ui/bin/geoip_IR.dat', 'x-ui/bin/geosite_IR.dat', 'x-ui/bin/geoip_RU.dat',
               'x-ui/bin/geosite_RU.dat', 'x-ui/bin/LICENSE', 'x-ui/bin/README.md'}
    found, total = set(), 0
    with tarfile.open(archive) as source:
        for member in source:
            if member.name not in allowed:
                continue
            if not member.isfile() or member.name in found or member.size > MAX_ARCHIVE:
                raise ValueError('Unexpected backend archive member')
            total += member.size
            if total > 384 * 1024 * 1024:
                raise ValueError('Backend archive expands beyond limit')
            target = destination / member.name.removeprefix('x-ui/')
            target.parent.mkdir(parents=True, exist_ok=True)
            payload = source.extractfile(member).read()
            executable = member.name == 'x-ui/x-ui' or member.name.endswith('xray-linux-'+arch)
            if executable and not payload.startswith(b'\x7fELF'):
                raise ValueError('Backend binary is not ELF')
            target.write_bytes(payload);target.chmod(0o755 if executable else 0o644)
            found.add(member.name)
    if not {'x-ui/x-ui', 'x-ui/bin/xray-linux-'+arch} <= found:
        raise ValueError('Backend binaries missing')


def initial_settings():
    """Our own minimal Xray configuration, only for a fresh isolated database."""
    config = {'log': {'loglevel': 'warning'}, 'stats': {},
              'api': {'tag': 'api', 'services': ['HandlerService', 'LoggerService', 'StatsService']},
              'inbounds': [{'listen': '127.0.0.1', 'port': 20541, 'protocol': 'dokodemo-door',
                            'settings': {'address': '127.0.0.1'}, 'tag': 'api'}],
              'outbounds': [{'protocol': 'freedom', 'tag': 'direct'}, {'protocol': 'blackhole', 'tag': 'blocked'}],
              'routing': {'rules': [{'type': 'field', 'inboundTag': ['api'], 'outboundTag': 'api'}]},
              'policy': {'levels': {'0': {'statsUserUplink': True, 'statsUserDownlink': True}},
                         'system': {'statsInboundUplink': True, 'statsInboundDownlink': True}}}
    return {'subEnable': 'false', 'subJsonEnable': 'false', 'subClashEnable': 'false',
            'subListen': '127.0.0.1', 'subPort': '20540', 'xrayTemplateConfig': json.dumps(config)}


class Backend:
    def __init__(self, root='/var/lib/donino-vpn-backend', release='/opt/donino-vpn-backend', units='/etc/systemd/system'):
        self.root, self.release, self.units = Path(root), Path(release), Path(units)
        self.private = self.root.parent/'donino-vpn-private'

    def run(self, args, *, env=None, timeout=30):
        result = subprocess.run(args, capture_output=True, text=True, env=env, timeout=timeout)
        if result.returncode:
            # stdout/stderr may include CLI-generated credentials. Never relay it.
            raise ValueError('Backend prerequisite or service command failed; inspect the local systemd service.')
        return result.stdout

    def status(self):
        receipt = self.private/'connection.json'
        if not receipt.exists():
            return {'installed': False, 'version': VERSION, 'port': PORT, 'scope': 'local-node'}
        connection = json.loads(receipt.read_text())
        result = subprocess.run(['systemctl', 'is-active', UNIT], capture_output=True, text=True, timeout=10)
        return {'installed': True, 'active': result.returncode == 0, 'version': connection['version'],
                'port': PORT, 'unit': UNIT, 'scope': 'local-node'}

    def install(self, body):
        if not isinstance(body, dict) or set(body) != {'confirm_install'} or body['confirm_install'] is not True:
            raise ValueError('Confirm isolated backend installation explicitly')
        if os.geteuid() != 0 or platform.system() != 'Linux' or not Path('/run/systemd/system').exists():
            raise ValueError('Backend installation requires a root systemd worker on Linux')
        if not INSTALL_LOCK.acquire(blocking=False):
            raise ValueError('A backend operation is already running; check status before retrying')
        try:
            receipt = self.private/'connection.json'
            if receipt.exists():
                # Retry returns the original receipt; never rotate an existing token.
                return json.loads(receipt.read_text())
            arch = {'x86_64': 'amd64', 'aarch64': 'arm64', 'arm64': 'arm64'}.get(platform.machine())
            if arch not in CHECKSUMS:
                raise ValueError('Backend supports Linux amd64 and arm64')
            self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
            self.root.chmod(0o700)
            unit = self.units/UNIT
            # Recoverable partial installs are not overwritten through the API.
            if unit.exists() or self.release.exists() or (self.root/'db').exists():
                raise ValueError('A partial or existing backend installation needs local recovery; existing data was preserved')
            for port in (PORT, 20541):
                with socket.socket() as listener:
                    listener.bind(('127.0.0.1', port))
            if shutil.disk_usage(self.root).free < 512*1024*1024:
                raise ValueError('At least 512 MiB free disk is required for backend installation')
            self.run(['systemctl', '--version'])
            try:
                self.run(['id', '-u', 'donino-vpn'])
            except ValueError:
                self.run(['useradd', '--system', '--user-group', '--home', str(self.root), '--shell', '/usr/sbin/nologin', 'donino-vpn'])
            import pwd
            account = pwd.getpwnam('donino-vpn')
            env = dict(os.environ, XUI_DB_FOLDER=str(self.root/'db'), XUI_BIN_FOLDER=str(self.root/'bin'),
                       XUI_LOG_FOLDER=str(self.root/'log'), XUI_MAIN_FOLDER=str(self.release),
                       XUI_NODE_UPDATE_POLICY='disabled')
            with tempfile.TemporaryDirectory(prefix='donino-vpn-') as temp:
                archive = Path(temp)/'backend.tar.gz'
                request = urllib.request.Request(f'https://github.com/MHSanaei/3x-ui/releases/download/{VERSION}/x-ui-linux-{arch}.tar.gz',
                                                 headers={'User-Agent': 'Donino-Ecosystem/0.4'})
                digest = hashlib.sha256();length = 0
                with urllib.request.urlopen(request, timeout=60) as response, archive.open('wb') as output:
                    if not response.url.startswith('https://'):
                        raise ValueError('Insecure backend redirect')
                    while chunk := response.read(1024*1024):
                        length += len(chunk)
                        if length > MAX_ARCHIVE:
                            raise ValueError('Backend archive exceeds limit')
                        digest.update(chunk);output.write(chunk)
                if digest.hexdigest() != CHECKSUMS[arch]:
                    raise ValueError('Backend archive SHA256 mismatch')
                stage = Path(temp)/'stage';extract(archive, stage, arch)
                self.release.mkdir(parents=True)
                shutil.copy2(stage/'x-ui', self.release/'x-ui')
                shutil.copy2(Path(__file__).parent/'resources'/'3x-ui-GPL-3.0.txt', self.release/'COPYING')
                (self.release/'UPSTREAM.txt').write_text('3x-ui '+VERSION+'\nSource: https://github.com/MHSanaei/3x-ui/tree/'+VERSION+'\nXray binaries retain their upstream MPL-2.0 license (bin/LICENSE).\n')
                shutil.copytree(stage/'bin', self.root/'bin')
            for directory in ('db', 'log'):
                (self.root/directory).mkdir(mode=0o700)
            import secrets
            base = '/' + secrets.token_hex(16) + '/'
            username, password = 'donino-'+secrets.token_hex(4), secrets.token_urlsafe(32)
            binary = str(self.release/'x-ui')
            self.run([binary, 'setting', '-port', str(PORT), '-listenIP', '127.0.0.1', '-webBasePath', base,
                      '-username', username, '-password', password], env=env)
            import sqlite3
            # Only the fresh, private database we just initialized. Existing
            # installations are rejected above and never opened or migrated.
            with sqlite3.connect(self.root/'db'/'x-ui.db') as db:
                if {r[1] for r in db.execute('PRAGMA table_info(settings)')} != {'id', 'key', 'value'}:
                    raise ValueError('Pinned backend settings schema changed unexpectedly')
                for key, value in initial_settings().items():
                    db.execute('DELETE FROM settings WHERE key=?', (key,))
                    db.execute('INSERT INTO settings(key,value) VALUES (?,?)', (key, value))
            output = self.run([binary, 'setting', '-getApiToken', '-tokenName', 'donino-control', '-tokenScope', 'admin'], env=env)
            match = re.search(r'^apiToken:\s*(\S+)\s*$', output, re.M)
            if not match:
                raise ValueError('Backend did not issue an API token; preserve the installation for local recovery')
            connection = {'version': VERSION, 'url': 'http://127.0.0.1:'+str(PORT)+base.rstrip('/'),
                          'kind': '3x-ui', 'token': match[1], 'name': 'Donino Xray · '+platform.node()[:40], 'writable': True}
            # All vendor runtime writes stay under the backend account; its API
            # cannot edit Donino root-worker files or existing VPN installations.
            for path in (self.root, *self.root.rglob('*')):
                os.chown(path, account.pw_uid, account.pw_gid)
            service = f'''[Unit]
Description=Donino isolated 3x-ui {VERSION} / Xray backend
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=donino-vpn
Group=donino-vpn
WorkingDirectory={self.root}
Environment=XUI_DB_FOLDER={self.root}/db
Environment=XUI_BIN_FOLDER={self.root}/bin
Environment=XUI_LOG_FOLDER={self.root}/log
Environment=XUI_MAIN_FOLDER={self.release}
ExecStart={self.release}/x-ui run
Restart=on-failure
RestartSec=3
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths={self.root}
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
[Install]
WantedBy=multi-user.target
'''
            unit.write_text(service);unit.chmod(0o644)
            self.run(['systemctl', 'daemon-reload'])
            try:
                self.run(['systemctl', 'enable', '--now', UNIT])
                # Receipt only after a live authenticated read, not just process startup.
                import time
                for attempt in range(20):
                    try:
                        req = urllib.request.Request(connection['url']+'/panel/api/clients/list', headers={'Authorization':'Bearer '+connection['token']})
                        # Local management never travels through an environment proxy.
                        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=2) as response:
                            result = json.load(response)
                        if result.get('success') is True:
                            break
                    except (OSError, ValueError):
                        pass
                    time.sleep(.5)
                else:
                    raise ValueError('Backend API did not become ready; installation preserved for recovery')
            except BaseException:
                subprocess.run(['systemctl', 'disable', '--now', UNIT], capture_output=True, timeout=20)
                raise
            # Root-owned receipts stay outside service-writable directory.
            receipt_dir = self.private
            receipt_dir.mkdir(mode=0o700, exist_ok=True);receipt_dir.chmod(0o700)
            atomic_json(receipt_dir/'admin.json', {'username': username, 'password': password, **connection})
            # Service account can write its state, so receipts must not be trusted
            # from that tree. A root-controlled symlink is not sufficient either.
            atomic_json(receipt_dir/'connection.json', connection)
            return connection
        finally:
            INSTALL_LOCK.release()
