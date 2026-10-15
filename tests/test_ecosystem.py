import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from donino_link.ecosystem import Ecosystem, ProviderError, base_url
from donino_link.store import Store
from donino_link.config import atomic_json
from donino_link.gateway import Gateway
from donino_link.panel import Panel, password_record
from test_core import configuration, PASSWORD


class EcosystemTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = Store(self.root/'state.db')
        self.eco = Ecosystem(self.store, self.root/'private.json')
        self.user = {'username': 'alice', 'status': 'active', 'data_limit': 1024,
                     'used_traffic': 128, 'expire': '2030-01-01T00:00:00Z', 'note': 'hello',
                     'subscription_url': '/sub/private-alice', 'proxy_settings': {'vless': {'id': 'SECRET-UUID'}}}
        self.client = {'id': 'SECRET-UUID', 'email': 'alice', 'enable': True, 'totalGB': 1024,
                       'expiryTime': 1893456000000, 'subId': 'SECRET-SUB', 'flow': '', 'comment': 'hello',
                       'customVendorField': 'preserved'}
        self.calls = []
        self.fail = False
        self.redirect = False
        self.xui3 = False
        self.inbound = {'id': 7, 'protocol': 'vless', 'port': 8443, 'remark': 'Donino',
                        'settings': json.dumps({'clients': [self.client]}),
                        'clientStats': [{'email': 'alice', 'up': 1, 'down': 2}]}
        async def handler(request):
            body = await request.json() if request.content_type == 'application/json' and request.can_read_body else dict(await request.post())
            self.calls.append((request.method, request.path, body, request.headers.get('Authorization')))
            if self.redirect:
                raise web.HTTPFound('/LEAK')
            if self.fail:
                return web.json_response({'secret': 'SHOULD-NOT-LEAK'}, status=403)
            if request.path == '/login':
                response = web.json_response({'success': True})
                response.set_cookie('session', 'test-only')
                return response
            if request.path.startswith('/panel/'):
                if not self.xui3 and request.cookies.get('session') != 'test-only':
                    return web.json_response({'success': False})
                obj = None
                if request.path.endswith('/inbounds/list'):
                    self.inbound['settings'] = json.dumps({'clients': [self.client]})
                    obj = [self.inbound]
                elif request.path.endswith('/inbounds/get/7'):
                    self.inbound['settings'] = json.dumps({'clients': [self.client]})
                    obj = self.inbound
                elif request.path.endswith('/clients/list'):
                    obj = [dict(self.client, inboundIds=[7], traffic={'up': 1, 'down': 2})]
                elif request.path.endswith('/clients/get/alice'):
                    obj = {'client': self.client, 'inboundIds': [7]}
                elif request.path.endswith('/clients/links/alice'):
                    obj = ['vless://SECRET-UUID@example.com:443']
                elif '/updateClient/' in request.path or request.path.endswith('/addClient'):
                    self.client = json.loads(body['settings'])['clients'][0]
                elif '/clients/update/' in request.path:
                    self.client = body
                elif request.path.endswith('/clients/add'):
                    self.client = body['client']
                return web.json_response({'success': True, 'obj': obj})
            if request.path == '/api/users':
                return web.json_response({'users': [self.user], 'total': 1})
            if request.path == '/api/user/alice':
                if request.method == 'PUT':
                    self.user.update(body)
                return web.json_response(self.user)
            if request.path == '/api/user':
                return web.json_response(dict(self.user, **body), status=201)
            if request.path == '/api/inbounds':
                return web.json_response(['vless-in'])
            if request.path == '/api/nodes':
                return web.json_response({'nodes': [{'id': 1, 'name': 'exit', 'status': 'connected', 'secret': 'NODE-SECRET'}]})
            if request.path.endswith('/reset'):
                return web.json_response(self.user)
            raise web.HTTPNotFound()
        app = web.Application()
        app.router.add_route('*', '/{path:.*}', handler)
        self.server = TestServer(app)
        await self.server.start_server()
        self.url = str(self.server.make_url('')).rstrip('/')

    async def asyncTearDown(self):
        await self.server.close()
        self.store.close()
        self.tmp.cleanup()

    async def connect(self, kind='pasarguard', write=True, **extra):
        return await self.eco.connect(dict(name='Europe', kind=kind, url=self.url, token='PRIVATE-API-TOKEN',
                                           writable=write, username='operator', password='PRIVATE-PASSWORD', **extra))

    async def test_registration_private_restart_and_export(self):
        config = await self.connect(auth='apikey')
        self.assertEqual(self.calls[-1][3], 'ApiKey PRIVATE-API-TOKEN')
        self.assertEqual((self.root/'private.json').stat().st_mode & 0o777, 0o600)
        restored = Ecosystem(self.store, self.root/'private.json')
        self.assertEqual(restored.state(), self.eco.state())
        report = json.dumps(self.eco.state()) + json.dumps(self.store.events())
        for secret in ('PRIVATE-API-TOKEN', 'PRIVATE-PASSWORD'):
            self.assertNotIn(secret, report)
        data = await self.eco.users(config['id'])
        for secret in ('SECRET-UUID', 'private-alice', 'PRIVATE-API-TOKEN'):
            self.assertNotIn(secret, json.dumps(data))
        self.assertEqual(data['users'][0]['expires'], 1893456000)
        self.assertEqual(data['users'][0]['used'], 128)
        inventory = await self.eco.inventory(config['id'])
        self.assertEqual(inventory['nodes'][0]['name'], 'exit')
        self.assertNotIn('NODE-SECRET', json.dumps(inventory))
        self.assertEqual((await self.eco.subscription(config['id'], 'alice'))['url'], self.url+'/sub/private-alice')
        await self.eco.disconnect(config['id'])
        self.assertEqual(self.eco.state()['connections'], [])
        self.assertEqual(json.loads((self.root/'private.json').read_text()), [])
        self.assertFalse(any(method != 'GET' for method, *_ in self.calls))

    async def test_failed_or_redirected_connection_is_never_saved(self):
        for redirect in (False, True):
            self.redirect = redirect; self.fail = not redirect
            with self.assertRaises(ProviderError) as error:
                await self.connect()
            self.assertNotIn('SHOULD-NOT-LEAK', str(error.exception))
            self.assertFalse((self.root/'private.json').exists())
        self.assertFalse(any(path == '/LEAK' for _, path, *_ in self.calls))

    async def test_read_only_mutation_and_bad_inputs_are_rejected(self):
        config = await self.connect(write=False)
        before = len(self.calls)
        with self.assertRaises(ValueError):
            await self.eco.mutate(config['id'], {'operation': 'create', 'username': 'alice'})
        self.assertEqual(len(self.calls), before)
        for body in ({'operation': 'delete'}, {'operation': 'create', 'command': 'bad'}):
            with self.assertRaises(ValueError):
                await self.eco.mutate(config['id'], body)
        for url in ('http://example.com', 'http://localhost:80', 'https://x/?a=secret', 'https://a:b@example.com',
                    'https://169.254.169.254', 'https://example.com/../admin', 'https://example.com/%2e'):
            with self.assertRaises(ValueError, msg=url): base_url(url)
        self.assertEqual(base_url('http://[::1]:8090/base/'), 'http://[::1]:8090/base')
        with self.assertRaises(ValueError): await self.eco.users(config['id'], limit=0)
        with self.assertRaises(ValueError): await self.connect()

    async def test_pasarguard_edit_optimistic_conflict_and_no_secret_return(self):
        config = await self.connect()
        row = (await self.eco.users(config['id']))['users'][0]
        await self.eco.mutate(config['id'], {'operation': 'update', 'key': row['key'], 'revision': row['revision'],
                                            'limit': 4096, 'expires': 0, 'enabled': False})
        self.assertEqual(self.calls[-1][:2], ('PUT', '/api/user/alice'))
        self.assertEqual(self.calls[-1][2], {'data_limit': 4096, 'expire': None, 'status': 'disabled'})
        before = sum(m == 'PUT' for m, *_ in self.calls)
        with self.assertRaisesRegex(ValueError, 'تغییر'):
            await self.eco.mutate(config['id'], {'operation': 'update', 'key': row['key'], 'revision': row['revision'], 'enabled': True})
        self.assertEqual(sum(m == 'PUT' for m, *_ in self.calls), before)
        row = (await self.eco.users(config['id']))['users'][0]
        await self.eco.mutate(config['id'], {'operation': 'reset', 'key': row['key'], 'revision': row['revision']})
        self.assertEqual(self.calls[-1][:2], ('POST', '/api/user/alice/reset'))
        with self.assertRaises(ValueError):
            await self.eco.mutate(config['id'], {'operation': 'create', 'username': 'new', 'limit': True})

    async def test_xui_v3_client_preserves_settings_and_contract(self):
        self.xui3 = True
        config = await self.connect(kind='3x-ui')
        row = (await self.eco.users(config['id']))['users'][0]
        self.assertEqual(row['used'], 3)
        await self.eco.mutate(config['id'], {'operation': 'update', 'key': row['key'], 'revision': row['revision'], 'enabled': False})
        self.assertFalse(self.client['enable'])
        self.assertEqual(self.client['customVendorField'], 'preserved')
        self.assertEqual(self.client['id'], 'SECRET-UUID')
        self.assertNotIn('traffic', self.calls[-1][2])
        self.assertIn('vless://SECRET-UUID', (await self.eco.subscription(config['id'], 'alice'))['links'][0])
        await self.eco.mutate(config['id'], {'operation': 'create', 'username': 'bob', 'inbounds': [7], 'limit': 100, 'expires': 0})
        self.assertEqual(self.calls[-1][1], '/panel/api/clients/add')
        self.assertEqual(self.calls[-1][2]['inboundIds'], [7])
        self.assertEqual(self.client['totalGB'], 100)
        self.assertNotEqual(self.client['id'], 'SECRET-UUID')

    async def test_legacy_cookie_identity_preserved_and_subscription_unavailable(self):
        config = await self.connect(kind='3x-ui-legacy')
        data = await self.eco.users(config['id'])
        row = data['users'][0]
        self.assertEqual(row['key'], '7:alice')
        self.assertFalse(row['subscription'])
        self.client['expiryTime'] = -86400000
        row = (await self.eco.users(config['id']))['users'][0]
        self.assertEqual(row['expires'], -86400)
        await self.eco.mutate(config['id'], {'operation': 'update', 'key': row['key'], 'revision': row['revision'], 'limit': 4096})
        self.assertEqual(self.calls[-1][1], '/panel/api/inbounds/updateClient/SECRET-UUID')
        self.assertEqual(self.client['expiryTime'], -86400000)
        self.assertEqual(self.client['totalGB'], 4096)
        self.assertEqual(self.client['customVendorField'], 'preserved')
        with self.assertRaises(ValueError): await self.eco.subscription(config['id'], row['key'])

    async def test_inbound_preview_is_data_only_and_writes_require_permission(self):
        self.xui3 = True
        config = await self.connect(kind='3x-ui', write=False)
        before = len(self.calls)
        body = {'name': 'Reality', 'port': 8443, 'server_name': 'www.example.com', 'apply': False}
        preview = await self.eco.inbound(config['id'], body)
        self.assertEqual(preview['preview']['tunnel_target'], '127.0.0.1:8443')
        self.assertEqual(len(self.calls), before)
        with self.assertRaises(ValueError): await self.eco.inbound(config['id'], dict(body, apply=True))
        self.assertEqual(len(self.calls), before)
        for bad in (dict(body, port=20539), dict(body, server_name='https://bad.com'), dict(body, apply='yes')):
            with self.assertRaises(ValueError): await self.eco.inbound(config['id'], bad)

    async def test_panel_routes_require_session_csrf_and_exclude_private_backup(self):
        config = configuration(self.root)
        atomic_json(self.root/'admin.json', password_record(PASSWORD))
        (self.root/'api-token').write_text('test-api-token')
        gateway = Gateway(config, self.store)
        panel = Panel(gateway)
        client = TestClient(TestServer(panel.app))
        await client.start_server()
        try:
            self.assertEqual((await client.get('/api/ecosystem')).status, 401)
            response = await client.post('/api/login', json={'password': PASSWORD})
            csrf = (await response.json())['csrf']
            self.assertEqual((await client.post('/api/ecosystem/connections', json={})).status, 403)
            headers = {'X-CSRF-Token': csrf}
            response = await client.post('/api/ecosystem/connections', headers=headers,
                                        json={'name':'test','kind':'pasarguard','url':self.url,'token':'PRIVATE-API-TOKEN'})
            self.assertEqual(response.status, 200)
            connection = await response.json()
            self.assertNotIn('PRIVATE-API-TOKEN', json.dumps(connection))
            response = await client.get('/api/ecosystem/'+connection['id']+'/users?limit=0')
            self.assertEqual(response.status, 400)
            response = await client.delete('/api/ecosystem/connections/'+connection['id'], headers={'Origin':'https://evil.test', **headers})
            self.assertEqual(response.status, 403)
            exported = await (await client.get('/api/export')).text()
            self.assertNotIn('PRIVATE-API-TOKEN', exported)
            response = await client.delete('/api/ecosystem/connections/'+connection['id'], headers=headers)
            self.assertEqual(response.status, 200)
        finally:
            await client.close()
