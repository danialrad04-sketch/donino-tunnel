#!/usr/bin/env python3
"""Real pinned 3x-ui + Xray integration; no production credentials or servers.

All API and VPN listeners bind to loopback. Test-only cleartext VLESS remains
inside this host. The production wizard emits Reality, validated by Xray here.
"""
import argparse
import asyncio
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from donino_link.ecosystem import Ecosystem
from donino_link.store import Store
from donino_link.vpn_backend import VERSION, CHECKSUMS, extract, initial_settings


def free_ports(count):
    sockets = [socket.socket() for _ in range(count)]
    try:
        for item in sockets: item.bind(('127.0.0.1', 0))
        return [item.getsockname()[1] for item in sockets]
    finally:
        for item in sockets: item.close()


async def run(archive):
    import sqlite3
    if hashlib.sha256(archive.read_bytes()).hexdigest() != CHECKSUMS['amd64']:
        raise ValueError('Pinned 3x-ui SHA256 mismatch')
    checks = []
    with tempfile.TemporaryDirectory(prefix='donino-ecosystem-test-') as d:
        root = Path(d);extract(archive, root/'vendor', 'amd64')
        db = root/'db';db.mkdir()
        env = dict(os.environ, XUI_DB_FOLDER=str(db), XUI_BIN_FOLDER=str(root/'vendor/bin'), XUI_LOG_FOLDER=str(root/'logs'))
        binary = root/'vendor/x-ui';port, apiport, vpnport, clientport, realityport, echoport = free_ports(6)
        def command(*args):
            return subprocess.run([str(binary), *args], capture_output=True, text=True, env=env, check=True).stdout
        command('setting', '-port', str(port), '-listenIP', '127.0.0.1', '-webBasePath', '/donino-test/',
                '-username', 'integration', '-password', os.urandom(24).hex())
        settings = initial_settings();template = json.loads(settings['xrayTemplateConfig']);template['inbounds'][0]['port'] = apiport;template['log']['loglevel'] = 'debug'
        template['outbounds'][0]['settings'] = {'finalRules':[{'action':'allow','ip':['127.0.0.1'],'port':str(echoport)}]}
        settings['xrayTemplateConfig'] = json.dumps(template)
        with sqlite3.connect(db/'x-ui.db') as conn:
            for key, value in settings.items():
                conn.execute('DELETE FROM settings WHERE key=?', (key,))
                conn.execute('INSERT INTO settings(key,value) VALUES (?,?)', (key, value))
        output = command('setting', '-getApiToken', '-tokenName', 'integration', '-tokenScope', 'admin')
        token = re.search(r'^apiToken:\s*(\S+)', output, re.M)[1]
        log = (root/'vendor.log').open('w')
        process = subprocess.Popen([str(binary), 'run'], env=env, stdout=log, stderr=log)
        store = Store(root/'state.db');eco = Ecosystem(store, root/'connections.json')
        client_process = None;echo = None
        try:
            for attempt in range(60):
                try:
                    connected = await eco.connect({'name': 'Real 3x-ui', 'kind': '3x-ui',
                        'url': f'http://127.0.0.1:{port}/donino-test', 'token': token, 'writable': True})
                    break
                except ValueError:
                    if process.poll() is not None: raise RuntimeError('Vendor process exited')
                    await asyncio.sleep(.25)
            else: raise RuntimeError('Vendor API never became ready')
            provider = connected['id'];checks.append('real-api-authentication')
            # Exercise the actual production Reality wizard, not a request fixture.
            plan = await eco.inbound(provider, {'name': 'Donino Reality test', 'port': realityport,
                                               'server_name': 'www.microsoft.com', 'apply': False})
            assert plan['preview']['listen'] == '127.0.0.1'
            created = await eco.inbound(provider, {'name': 'Donino Reality test', 'port': realityport,
                                                  'server_name': 'www.microsoft.com', 'apply': True})
            assert created['inbound']['id']
            checks.append('real-reality-inbound-and-key-generation')
            async with eco.upstream(eco.find(provider)) as upstream:
                payload = {'remark': 'loopback integration only', 'enable': True, 'listen': '127.0.0.1',
                    'port': vpnport, 'protocol': 'vless', 'settings': json.dumps({'clients': [], 'decryption': 'none'}),
                    'streamSettings': json.dumps({'network': 'tcp', 'security': 'none'}),
                    'sniffing': json.dumps({'enabled': False, 'destOverride': []})}
                inbound = await upstream.call('POST', '/panel/api/inbounds/add', data=payload)
            await eco.mutate(provider, {'operation': 'create', 'username': 'donino-test', 'inbounds': [inbound['id']],
                                       'limit': 2**30, 'expires': 0, 'enabled': True, 'note': 'actual vendor integration'})
            row = (await eco.users(provider))['users'][0]
            assert row['username'] == 'donino-test' and row['limit'] == 2**30
            checks.append('real-client-create-and-normalized-list')
            async with eco.upstream(eco.find(provider)) as upstream:
                raw, _ = await eco.user(upstream, row['key'])
                installed = await upstream.call('GET', '/panel/api/inbounds/get/'+str(inbound['id']))
                assert installed['settings']['clients'][0]['id'] == raw['id'], 'Read/write UUID contract differs'
            async def echo_client(reader, writer):
                try:
                    data = await reader.read(10000);writer.write(data);await writer.drain()
                finally:
                    writer.close();await writer.wait_closed()
            echo = await asyncio.start_server(echo_client, '127.0.0.1', echoport)
            echoport = echo.sockets[0].getsockname()[1]
            clientconfig = {'log': {'loglevel': 'debug'}, 'inbounds': [{'listen': '127.0.0.1', 'port': clientport,
                'protocol': 'dokodemo-door', 'settings': {'address': '127.0.0.1', 'port': echoport, 'network': 'tcp'}}],
                'outbounds': [{'protocol': 'vless', 'settings': {'vnext': [{'address': '127.0.0.1', 'port': vpnport,
                    'users': [{'id': raw['id'], 'encryption': 'none'}]}]}, 'streamSettings': {'network': 'tcp', 'security': 'none'}}]}
            configpath = root/'client.json';configpath.write_text(json.dumps(clientconfig))
            xray = root/'vendor/bin/xray-linux-amd64'
            client_process = subprocess.Popen([str(xray), 'run', '-config', str(configpath)], stdout=log, stderr=log)
            async def probe():
                reader, writer = await asyncio.open_connection('127.0.0.1', clientport)
                try:
                    message = os.urandom(1024);writer.write(message);await writer.drain()
                    return await asyncio.wait_for(reader.readexactly(len(message)), 2) == message
                finally:
                    writer.close();await writer.wait_closed()
            for attempt in range(8):
                try:
                    if await probe(): break
                except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError): pass
                await asyncio.sleep(.25)
            else: raise RuntimeError('Actual Xray data plane never carried echo')
            checks.append('real-xray-client-server-vless-echo')
            links = await eco.subscription(provider, row['key'])
            assert links['links'] and any(raw['id'] in link for link in links['links'])
            checks.append('real-subscription-links')
            await eco.mutate(provider, {'operation': 'update', 'key': row['key'], 'revision': row['revision'], 'enabled': False})
            updated = (await eco.users(provider))['users'][0]
            assert updated['status'] == 'disabled'
            for attempt in range(40):
                try: ok = await probe()
                except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError): ok = False
                if not ok: break
                await asyncio.sleep(.25)
            else: raise RuntimeError('Disabled client still authenticated')
            checks.append('real-disable-enforced-by-xray')
            await eco.mutate(provider, {'operation': 'update', 'key': updated['key'], 'revision': updated['revision'], 'enabled': True})
            updated = (await eco.users(provider))['users'][0]
            await eco.mutate(provider, {'operation': 'reset', 'key': updated['key'], 'revision': updated['revision']})
            checks.append('real-enable-and-reset-traffic')
            async with eco.upstream(eco.find(provider)) as upstream:
                await upstream.call('POST', '/panel/api/server/restartXrayService')
            config = root/'vendor/bin/config.json'
            for attempt in range(20):
                parsed = json.loads(config.read_text())
                if any(r.get('port') == realityport for r in parsed.get('inbounds', [])): break
                await asyncio.sleep(.2)
            assert any(r.get('port') == realityport for r in parsed['inbounds']), 'Reality configuration was not materialized'
            result = subprocess.run([str(xray), 'run', '-test', '-config', str(config)], capture_output=True)
            assert result.returncode == 0, 'Vendor Reality configuration failed Xray validation'
            checks.append('actual-xray-validates-combined-reality-configuration')
            assert token not in json.dumps(eco.state()) + json.dumps(store.events())
            checks.append('observations-and-audit-exclude-api-token')
            return {'vendor': 'MHSanaei/3x-ui', 'version': VERSION, 'sha256': CHECKSUMS['amd64'],
                    'checks': checks, 'network': 'loopback-only', 'real_vps': False, 'result': 'passed'}
        except BaseException:
            # The log remains private and is never printed with tokens/profiles.
            target = Path('/tmp/donino-ecosystem-vendor-failure.log');target.write_text((root/'vendor.log').read_text());target.chmod(0o600)
            raise
        finally:
            for child in (client_process, process):
                if child is not None:
                    child.terminate()
                    try: child.wait(timeout=10)
                    except subprocess.TimeoutExpired: child.kill();child.wait()
            if echo:
                echo.close();await echo.wait_closed()
            store.close();log.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--archive', type=Path, default=Path('/tmp/donino-3x-ui-v3.10.2-amd64.tar.gz'))
    parser.add_argument('--output', type=Path, default=Path('ecosystem-results.json'))
    args = parser.parse_args()
    if not args.archive.exists():
        with urllib.request.urlopen(f'https://github.com/MHSanaei/3x-ui/releases/download/{VERSION}/x-ui-linux-amd64.tar.gz', timeout=60) as response, args.archive.open('wb') as output:
            total = 0
            while chunk := response.read(1024*1024):
                total += len(chunk)
                if total > 128*1024*1024: raise ValueError('Archive exceeds limit')
                output.write(chunk)
    result = asyncio.run(run(args.archive))
    args.output.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result))
