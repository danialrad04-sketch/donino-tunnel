import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from aiohttp.test_utils import TestClient,TestServer
from donino_link.config import endpoint,load_config,atomic_json
from donino_link.health import start_responder,probe,mac
from donino_link.store import Store
from donino_link.gateway import Gateway
from donino_link.panel import Panel,password_record,verify_password
from donino_link.raw_rules import rule_specs
from donino_link.deploy import ssh_args


KEY='ab'*32
PASSWORD='strong-test-password-123'


def configuration(tmp):
    return {'schema':1,'role':'iran','health_key':KEY,
            'services':[{'id':'echo','listen':'127.0.0.1:12345'}],
            'paths':[{'id':'primary','priority':10,'health':'127.0.0.1:12346','backends':{'echo':'127.0.0.1:12347'}},
                     {'id':'backup','priority':20,'health':'127.0.0.1:12348','backends':{'echo':'127.0.0.1:12349'}}],
            'policy':{'probe_interval':.1,'probe_timeout':.1,'failures':2,'recoveries':2,'connect_timeout':.2,'idle_timeout':1,'max_connections':20},
            'panel':{'listen':'127.0.0.1:12350','credentials_file':str(tmp/'admin.json'),'api_token_file':str(tmp/'api-token')},
            'state_db':str(tmp/'state.sqlite3')}


class ConfigTests(unittest.TestCase):
    def test_endpoint_validation(self):
        self.assertEqual(endpoint('[::1]:8080'),('::1',8080))
        for value in ['host:0','host:65536','::1:8080','$(bad):443','x;echo:443','host:abc']:
            with self.assertRaises(ValueError):endpoint(value)

    def test_public_panel_without_tls_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            tmp=Path(d);c=configuration(tmp);c['panel']['listen']='0.0.0.0:8090';atomic_json(tmp/'config',c)
            with self.assertRaises(ValueError):load_config(tmp/'config')

    def test_non_loopback_backend_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            tmp=Path(d);c=configuration(tmp);c['paths'][0]['backends']['echo']='1.2.3.4:443';atomic_json(tmp/'config',c)
            with self.assertRaises(ValueError):load_config(tmp/'config')

    def test_password(self):
        record=password_record(PASSWORD)
        self.assertTrue(verify_password(PASSWORD,record))
        self.assertFalse(verify_password('incorrect',record))
        self.assertNotIn(PASSWORD,json.dumps(record))
        with self.assertRaises(ValueError):password_record('short')

    def test_ssh_host_injection_rejected(self):
        for host in ['root@x;curl evil','-oProxyCommand=bad','root@$(bad)','root@x\nfoo']:
            with self.assertRaises(ValueError):ssh_args(host)
        self.assertIn('StrictHostKeyChecking=yes',ssh_args('root@192.0.2.1'))

    def test_raw_rules_scoped(self):
        rules=rule_specs('192.0.2.1',33434)
        for table,chain,spec in rules:
            self.assertIn('192.0.2.1',spec);self.assertIn('33434',spec);self.assertIn('donino-link-paqet',spec)
        with self.assertRaises(ValueError):rule_specs('192.0.2.1',443)


class AsyncTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmpobj=tempfile.TemporaryDirectory();self.tmp=Path(self.tmpobj.name)
        self.config=configuration(self.tmp)
        self.store=Store(self.tmp/'state.sqlite3')
        self.gateway=Gateway(self.config,self.store)
        self.servers=[]

    async def asyncTearDown(self):
        await self.gateway.stop()
        for s in self.servers:s.close()
        await asyncio.gather(*(s.wait_closed() for s in self.servers))
        self.store.close();self.tmpobj.cleanup()

    async def listen(self, callback):
        server=await asyncio.start_server(callback,'127.0.0.1',0)
        self.servers.append(server)
        return '127.0.0.1:'+str(server.sockets[0].getsockname()[1])

    async def health(self):
        server=await start_responder('127.0.0.1:12351',KEY)
        self.servers.append(server)
        return '127.0.0.1:12351'

    async def test_authentic_fresh_probe_and_wrong_key(self):
        address=await self.health()
        ms,stats=await probe(address,KEY,1)
        self.assertGreater(ms,0);self.assertIn('time',stats)
        with self.assertRaises((ValueError,KeyError,ConnectionError)):
            await probe(address,'cd'*32,1)

    async def test_fake_local_listener_is_not_healthy(self):
        async def fake(reader,writer):
            await reader.readline();writer.write(b'{"body":"{}","auth":"bad"}\n');await writer.drain();writer.close()
        address=await self.listen(fake)
        p=self.gateway.paths['primary'];p.config['health']=address
        await self.gateway.check(p);await self.gateway.check(p)
        self.assertFalse(p.healthy)

    async def test_hysteresis_and_recovery(self):
        address=await self.health();p=self.gateway.paths['primary'];p.config['health']=address
        await self.gateway.check(p);self.assertFalse(p.healthy)
        await self.gateway.check(p);self.assertTrue(p.healthy)
        p.config['health']='127.0.0.1:1'
        await self.gateway.check(p);self.assertTrue(p.healthy)
        await self.gateway.check(p);self.assertFalse(p.healthy)

    async def gateway_address(self):
        server=await asyncio.start_server(lambda r,w:self.gateway.handle(r,w,self.config['services'][0]),'127.0.0.1',0)
        self.gateway.servers.append(server)
        return ('127.0.0.1',server.sockets[0].getsockname()[1])

    async def test_passive_failover_preserves_payload(self):
        async def echo(reader,writer):
            while chunk:=await reader.read(65536):writer.write(chunk);await writer.drain()
            writer.close()
        address=await self.listen(echo)
        self.gateway.paths['primary'].config['backends']['echo']='127.0.0.1:1'
        self.gateway.paths['backup'].config['backends']['echo']=address
        for p in self.gateway.paths.values():p.healthy=True
        r,w=await asyncio.open_connection(*await self.gateway_address())
        payload=b'no replay or truncation'*20000
        w.write(payload);await w.drain()
        self.assertEqual(await asyncio.wait_for(r.readexactly(len(payload)),3),payload)
        w.close();await w.wait_closed();await asyncio.sleep(.03)
        self.assertFalse(self.gateway.paths['primary'].healthy)
        self.assertEqual(self.gateway.paths['backup'].bytes_up,len(payload))

    async def test_half_close_allows_delayed_response(self):
        async def after_eof(reader,writer):
            data=await reader.read();await asyncio.sleep(.02);writer.write(data.upper());await writer.drain();writer.close()
        address=await self.listen(after_eof)
        p=self.gateway.paths['primary'];p.healthy=True;p.config['backends']['echo']=address
        r,w=await asyncio.open_connection(*await self.gateway_address())
        w.write(b'half close');await w.drain();w.write_eof()
        self.assertEqual(await asyncio.wait_for(r.read(),1),b'HALF CLOSE')
        w.close();await w.wait_closed()

    async def test_drain_keeps_existing_connection(self):
        async def echo(r,w):
            while data:=await r.read(100):w.write(data);await w.drain()
            w.close()
        p=self.gateway.paths['primary'];p.healthy=True;p.config['backends']['echo']=await self.listen(echo)
        addr=await self.gateway_address();r,w=await asyncio.open_connection(*addr)
        w.write(b'first');await w.drain();self.assertEqual(await r.readexactly(5),b'first')
        self.gateway.action('primary','drain')
        w.write(b'still works');await w.drain();self.assertEqual(await r.readexactly(11),b'still works')
        r2,w2=await asyncio.open_connection(*addr)
        self.assertEqual(await asyncio.wait_for(r2.read(),1),b'')
        w2.close();await w2.wait_closed();w.close();await w.wait_closed()

    async def test_pause_and_persistent_choices(self):
        self.gateway.action('primary','disable');self.gateway.action(None,'pause')
        restored=Gateway(self.config,self.store)
        self.assertTrue(restored.paused);self.assertEqual(restored.paths['primary'].mode,'disabled')
        r,w=await asyncio.open_connection(*await self.gateway_address())
        self.assertEqual(await asyncio.wait_for(r.read(),1),b'')
        w.close();await w.wait_closed()

    async def panel_client(self):
        atomic_json(self.tmp/'admin.json',password_record(PASSWORD))
        (self.tmp/'api-token').write_text('private-api-token-for-testing')
        panel=Panel(self.gateway)
        client=TestClient(TestServer(panel.app));await client.start_server()
        self.addAsyncCleanup(client.close)
        return panel,client

    async def test_panel_auth_csrf_logout_and_no_secrets(self):
        panel,client=await self.panel_client()
        response=await client.get('/api/status');self.assertEqual(response.status,401)
        response=await client.get('/api/provision/state');self.assertEqual(response.status,401)
        response=await client.post('/api/provision/start',json={'plan_id':'a'*32,'confirm_replace':True});self.assertEqual(response.status,401)
        response=await client.post('/api/login',json={'password':PASSWORD});self.assertEqual(response.status,200)
        csrf=(await response.json())['csrf']
        self.assertTrue(response.cookies['donino_session']['httponly'])
        response=await client.get('/api/status');self.assertEqual(response.status,200)
        text=await response.text();self.assertNotIn(KEY,text);self.assertNotIn(PASSWORD,text)
        self.assertIn("frame-ancestors 'none'",response.headers['Content-Security-Policy'])
        response=await client.post('/api/action',json={'action':'pause'});self.assertEqual(response.status,403)
        response=await client.post('/api/provision/start',json={'plan_id':'a'*32,'confirm_replace':True});self.assertEqual(response.status,403)
        response=await client.get('/api/provision/state',headers={'X-CSRF-Token':csrf});self.assertEqual(response.status,200)
        response=await client.post('/api/provision/start',headers={'Origin':'https://evil.test','X-CSRF-Token':csrf},json={});self.assertEqual(response.status,403)
        response=await client.post('/api/action',headers={'X-CSRF-Token':csrf},json={'action':'pause'});self.assertEqual(response.status,200)
        response=await client.get('/api/status',headers={'Origin':'https://evil.test'});self.assertEqual(response.status,403)
        response=await client.post('/api/logout',headers={'X-CSRF-Token':csrf},json={});self.assertEqual(response.status,200)
        response=await client.get('/api/status');self.assertEqual(response.status,401)

    async def test_bearer_and_metrics(self):
        _,client=await self.panel_client()
        response=await client.get('/api/metrics',headers={'Authorization':'Bearer private-api-token-for-testing'})
        self.assertEqual(response.status,200);self.assertIn('donino_path_healthy',await response.text())
        response=await client.post('/api/action',headers={'Authorization':'Bearer private-api-token-for-testing'},json={'path':'primary','action':'prefer'})
        self.assertEqual(response.status,200)

    async def test_login_rate_limit(self):
        _,client=await self.panel_client()
        for _ in range(5):
            response=await client.post('/api/login',json={'password':'wrong'})
            self.assertEqual(response.status,401)
        response=await client.post('/api/login',json={'password':PASSWORD});self.assertEqual(response.status,429)


if __name__=='__main__':unittest.main()
