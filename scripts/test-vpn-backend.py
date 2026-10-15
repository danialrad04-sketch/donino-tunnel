#!/usr/bin/env python3
"""Fresh disposable root/systemd host only. Never run on a production VPS."""
import asyncio
import hashlib
import ssl
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import patch
from aiohttp import web
from aiohttp.test_utils import TestServer
import json
import os
import pwd
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from donino_link.vpn_backend import Backend, UNIT, VERSION
from donino_link.ecosystem import Ecosystem
from donino_link.store import Store


@asynccontextmanager
async def paired_bridge(root):
    from donino_link.config import atomic_json
    from donino_link.peer import ForeignAgent, application as peer_app, digest
    from donino_link.provision import application as worker_app
    live=root/'foreign.json'
    atomic_json(live,{'schema':1,'role':'foreign','health_key':'1'*64,'health_listen':'127.0.0.1:19090',
                     'targets':{},'panel':{'listen':'127.0.0.1:8091','allow_insecure_http':True}})
    cert,key=root/'agent.crt',root/'agent.key'
    subprocess.run(['openssl','req','-x509','-newkey','ed25519','-nodes','-days','1','-subj','/CN=backend-ci',
                    '-keyout',str(key),'-out',str(cert)],check=True,capture_output=True)
    pin=hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
    agent=ForeignAgent(root/'agent',live,{'fingerprint':pin,'port':9444,'ssh_port':22},lambda *args:None)
    token='ci-paired-agent-token'
    atomic_json(agent.root/'pairs.json',[{'id':'b'*32,'name':'CI Iran','source':'127.0.0.1',
        'management':'https-v1','token_digest':digest(token),'revoked':False}])
    tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.load_cert_chain(cert,key)
    server=TestServer(peer_app(agent,True),scheme='https');await server.start_server(ssl=tls)
    profile={'id':'a'*32,'host':'127.0.0.1','name':'CI outside','agent_port':server.port,
             'agent_fingerprint':pin,'agent_token':token}
    worker=SimpleNamespace(profile=lambda identifier:profile,task=None)
    runner=web.AppRunner(worker_app(worker));await runner.setup()
    sock=root/'controller.sock';site=web.UnixSite(runner,str(sock));await site.start()
    try:yield worker,sock
    finally:
        await runner.cleanup();await server.close()


async def main():
    backend = Backend()
    if os.geteuid() != 0 or not Path('/run/systemd/system').exists():
        raise RuntimeError('Disposable root/systemd host required')
    if any(p.exists() for p in (backend.root, backend.private, backend.release, backend.units/UNIT)):
        raise RuntimeError('Refusing to touch an existing backend installation')
    try:
        pwd.getpwnam('donino-vpn')
        raise RuntimeError('Refusing to use an existing backend account')
    except KeyError:
        pass
    checks=[]
    temporary=tempfile.TemporaryDirectory();context=paired_bridge(Path(temporary.name))
    worker,bridge_socket=await context.__aenter__()
    patcher=patch('donino_link.provision.SOCKET',bridge_socket);patcher.start()
    try:
        from donino_link.vpn_bridge import remote
        metadata=await remote(worker,{'profile_id':'a'*32,'operation':'install','confirm_install':True})
        connection=json.loads((backend.private/'connection.json').read_text())
        assert 'token' not in metadata
        checks.append('remote-bootstrap-over-pinned-https-without-exposing-vendor-token')
        assert backend.status()['active'];checks.append('actual-root-systemd-bootstrap')
        again = await asyncio.to_thread(backend.install, {'confirm_install':True})
        assert again == connection;checks.append('idempotent-install-keeps-token')
        uid=pwd.getpwnam('donino-vpn').pw_uid
        assert backend.root.stat().st_uid == uid
        assert (backend.private/'connection.json').stat().st_uid == 0
        assert (backend.private/'connection.json').stat().st_mode & 0o777 == 0o600
        result=subprocess.run(['runuser','-u','donino-vpn','--','cat',str(backend.private/'connection.json')],capture_output=True)
        assert result.returncode != 0;checks.append('service-account-cannot-read-root-receipt')
        with sqlite3.connect(backend.root/'db/x-ui.db') as db:
            settings=dict(db.execute('SELECT key,value FROM settings'))
        assert settings['subEnable']=='false' and settings['subListen']=='127.0.0.1'
        assert json.loads(settings['xrayTemplateConfig'])['inbounds'][0]['port']==20541
        listeners=subprocess.check_output(['ss','-lnt'],text=True)
        for line in listeners.splitlines():
            if ':20539 ' in line or ':20541 ' in line: assert '127.0.0.1:' in line
        checks.append('management-api-local-and-public-subscription-disabled')
        with tempfile.TemporaryDirectory() as d:
            store=Store(Path(d)/'state.db');eco=Ecosystem(store,Path(d)/'connections.json')
            config=await eco.connect({k:metadata[k] for k in ('name','kind','url','writable')},peer_profile=metadata['peer_profile'])
            checks.append('real-provider-api-through-central-unix-and-pinned-https-bridge')
            with socket.socket() as listener:
                listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
            made=await eco.inbound(config['id'], {'name':'CI Reality','port':port,'server_name':'www.example.com','apply':True})
            await eco.mutate(config['id'], {'operation':'create','username':'ci-client','inbounds':[made['inbound']['id']], 'limit':2**30})
            assert (await eco.users(config['id']))['total']==1
            checks.append('managed-account-and-reality-inbound-through-real-adapter')
            from aiohttp import ClientSession
            async with ClientSession(trust_env=False) as direct:
                async with direct.get(connection['url']+'/panel/api/server/status',headers={'Authorization':'Bearer '+connection['token']}) as response:
                    status=await response.json()
            assert status['obj']['xray']['state']=='running'
            checks.append('unprivileged-systemd-xray-core-is-running')
            subprocess.run(['systemctl','restart',UNIT],check=True)
            for attempt in range(40):
                try:
                    result=await eco.users(config['id'])
                    if result['total']==1: break
                except ValueError: pass
                await asyncio.sleep(.25)
            else: raise RuntimeError('Backend did not recover after restart')
            checks.append('users-and-token-survive-service-restart');store.close()
        result={'version':VERSION,'systemd':True,'checks':checks,'result':'passed'}
        Path('vpn-backend-results.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
    finally:
        patcher.stop()
        await context.__aexit__(None,None,None);temporary.cleanup()
        subprocess.run(['systemctl','disable','--now',UNIT],capture_output=True,timeout=30)
        (backend.units/UNIT).unlink(missing_ok=True)
        subprocess.run(['systemctl','daemon-reload'],capture_output=True,timeout=30)
        for directory in (backend.root,backend.private,backend.release):
            if directory.exists(): shutil.rmtree(directory)
        subprocess.run(['userdel','donino-vpn'],capture_output=True,timeout=30)

if __name__=='__main__': asyncio.run(main())
