#!/usr/bin/env python3
"""Browser checks against the real authenticated Donino panel + declared vendor fixture."""
import asyncio
import json
import os
import tempfile
import sys
from pathlib import Path
from aiohttp import web
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from donino_link.config import atomic_json
from donino_link.panel import Panel, password_record
from donino_link.gateway import Gateway
from donino_link.store import Store


async def main():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        atomic_json(root/'admin.json', password_record('ecosystem-browser-password'))
        (root/'token').write_text('browser-fixture-api-token')
        store = Store(root/'state.db')
        config = {'role': 'iran', 'schema': 1, 'health_key': 'ab'*32, 'services': [], 'paths': [],
                  'policy': {'probe_interval':3,'probe_timeout':2,'failures':2,'recoveries':2,'max_connections':512,'connect_timeout':5,'idle_timeout':60},
                  'panel': {'listen': '127.0.0.1:18090','credentials_file': str(root/'admin.json'), 'api_token_file': str(root/'token')},
                  'state_db': str(root/'state.db'), 'bootstrap': True}
        gateway = Gateway(config, store);panel = Panel(gateway)
        users = [{'username': 'alice', 'status': 'active', 'used_traffic': 1024, 'data_limit': 2**30,
                  'expire': None, 'note': 'fixture user', 'subscription_url': '/sub/fixture-private', 'proxy_settings': {'vless': {'id':'FIXTURE-SECRET'}}}]
        async def vendor(request):
            if request.headers.get('Authorization') != 'Bearer fixture-vendor-token':
                return web.json_response({'error':'incorrect fixture token'}, status=401)
            if request.path == '/api/users':
                q = request.query.get('username','');rows = [r for r in users if q in r['username']]
                return web.json_response({'users': rows[int(request.query.get('offset',0)):][:int(request.query.get('limit',50))], 'total':len(rows)})
            if request.path == '/api/inbounds': return web.json_response(['VLESS Reality'])
            if request.path == '/api/nodes': return web.json_response({'nodes':[{'id':1,'name':'Exit Europe','status':'connected'}]})
            if request.path == '/api/user' and request.method == 'POST':
                body = await request.json();row = dict(users[0], **body);row['used_traffic']=0;users.append(row);return web.json_response(row, status=201)
            if request.path.startswith('/api/user/'):
                name = request.match_info['tail'].split('/')[2];row = next(r for r in users if r['username']==name)
                if request.method == 'PUT': row.update(await request.json())
                return web.json_response(row)
            raise web.HTTPNotFound()
        fixture = web.Application();fixture.router.add_route('*','/{tail:.*}',vendor)
        vendor_runner = web.AppRunner(fixture);await vendor_runner.setup();vendor_site = web.TCPSite(vendor_runner,'127.0.0.1',0);await vendor_site.start()
        runner=web.AppRunner(panel.app,access_log=None);await runner.setup();site=web.TCPSite(runner,'127.0.0.1',0);await site.start()
        env = dict(os.environ, DONINO_ECO_UI_URL='http://127.0.0.1:'+str(site._server.sockets[0].getsockname()[1]),
                   DONINO_ECO_VENDOR_URL='http://127.0.0.1:'+str(vendor_site._server.sockets[0].getsockname()[1]))
        try:
            process = await asyncio.create_subprocess_exec('node','scripts/test-ecosystem-ui.cjs',env=env)
            code = await process.wait()
            if code: raise RuntimeError('Ecosystem browser checks failed')
        finally:
            await runner.cleanup();await vendor_runner.cleanup();store.close()

if __name__=='__main__': asyncio.run(main())
