import asyncio
import hashlib
import json
import ssl
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch,AsyncMock
from aiohttp import web,ServerFingerprintMismatch
from aiohttp.test_utils import TestClient,TestServer
from donino_link.config import atomic_json,load_config
from donino_link.peer import ForeignAgent,application,split_code,key_fields,peer_request,digest
from donino_link.bootstrap import make_bootstrap
from donino_link.foreign import ForeignMonitor
from donino_link.store import Store


class PeerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.live=self.root/'node.json'
        atomic_json(self.live,{'schema':1,'role':'foreign','health_key':'1'*64,'health_listen':'127.0.0.1:19090','targets':{'app':'127.0.0.1:18081'},'panel':{'listen':'0.0.0.0:8091','allow_insecure_http':True}})
        atomic_json(self.root/'install.json',{'units':['donino-link.service','donino-link-frp-wss.service']})
        subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(self.root/'identity')],check=True)
        self.key=(self.root/'identity.pub').read_text().strip();self.writes=[]
        self.agent=ForeignAgent(self.root/'agent',self.live,{'fingerprint':'a'*64,'port':9444,'ssh_port':22},lambda root,pairs:self.writes.append(json.loads(json.dumps(pairs))))
        self.client=TestClient(TestServer(application(self.agent,True)));await self.client.start_server()

    async def asyncTearDown(self):
        await self.client.close();await asyncio.gather(*list(self.agent.tasks),return_exceptions=True);self.tmp.cleanup()

    def exchange(self,code=None):
        code=code or self.agent.pairing_code()['code'];pin,token=split_code(code)
        with patch('donino_link.peer.subprocess.check_output',return_value='256 SHA256:'+'b'*43+' host (ED25519)'):
            result=self.agent.exchange({'token':token,'public_key':self.key,'name':'Iran'},'127.0.0.1')
        return result

    async def test_expiring_single_use_pairing_and_no_secret_in_state(self):
        code=self.agent.pairing_code()['code'];result=self.exchange(code)
        with self.assertRaisesRegex(ValueError,'expired, used'):self.exchange(code)
        self.assertEqual(self.writes[-1][0]['public_key'],key_fields(self.key))
        public=json.dumps(self.agent.state())
        self.assertNotIn(result['agent_token'],public);self.assertNotIn('token_digest',public);self.assertNotIn('PRIVATE KEY',public)
        with self.assertRaises(web.HTTPUnauthorized):self.agent.authenticate('Bearer '+result['agent_token'],'127.0.0.2')
        pair=self.agent.authenticate('Bearer '+result['agent_token'],'127.0.0.1')
        self.assertEqual(pair['id'],result['pair_id'])
        pending=self.agent.pairing_code()['code'];data=json.loads((self.agent.root/'pending.json').read_text());data['expires']=time.time()-1;atomic_json(self.agent.root/'pending.json',data)
        with self.assertRaises(ValueError):self.exchange(pending)

    async def test_pairing_does_not_accept_private_keys_commands_or_algorithms(self):
        for value in ['-----BEGIN PRIVATE KEY-----','ssh-rsa AAAA','ssh-ed25519 AAAA','ssh-ed25519 invalid']:
            with self.assertRaises(ValueError):key_fields(value)
        code=self.agent.pairing_code()['code'];_,token=split_code(code)
        with self.assertRaises(ValueError):self.agent.exchange({'token':token,'public_key':self.key,'name':'Iran','command':'whoami'},'127.0.0.1')
        self.assertTrue((self.agent.root/'pending.json').exists())
        self.assertEqual((await self.client.post('/action',json={'unit':'ssh.service','action':'stop'})).status,404)
        self.assertEqual((await self.client.post('/code',json={})).status,404)

    async def test_remote_authentication_lease_and_revocation(self):
        result=self.exchange();pair=self.agent.authenticate('Bearer '+result['agent_token'],'127.0.0.1')
        response=await self.client.post('/lease',json={'job_id':'b'*32});self.assertEqual(response.status,401)
        self.agent.reserve(pair,{'job_id':'b'*32})
        with self.assertRaisesRegex(ValueError,'running'):self.agent.revoke(pair['id'])
        with self.assertRaises(ValueError):await self.agent.action({'unit':'donino-link.service','action':'restart'})
        self.agent.release(pair,{'job_id':'c'*32});self.assertIsNotNone(self.agent.lease())
        self.agent.release(pair,{'job_id':'b'*32});self.assertIsNone(self.agent.lease())
        self.agent.revoke(pair['id'])
        with self.assertRaises(web.HTTPUnauthorized):self.agent.authenticate('Bearer '+result['agent_token'],'127.0.0.1')
        self.assertTrue(self.writes[-1][0]['revoked'])

    async def test_actions_are_fixed_managed_units_and_logged_truthfully(self):
        with self.assertRaises(ValueError):await self.agent.action({'unit':'ssh.service','action':'stop'})
        with self.assertRaisesRegex(ValueError,'cannot stop itself'):await self.agent.action({'unit':'donino-link.service','action':'stop'})
        with self.assertRaises(ValueError):await self.agent.action({'unit':'donino-link.service','action':'restart','command':'id'})
        with patch('donino_link.peer.subprocess.run',return_value=subprocess.CompletedProcess([],1)) as command:
            result=await self.agent.action({'unit':'donino-link-frp-wss.service','action':'restart'})
            await asyncio.gather(*list(self.agent.tasks))
            self.assertEqual(self.agent.state()['actions'][0]['status'],'failed')
            self.assertEqual(command.call_args.args[0],['systemctl','restart','donino-link-frp-wss.service'])
        self.assertFalse(self.agent.action_busy)

    async def test_telemetry_requires_matching_installation_and_typed_targets(self):
        pair={'id':'a'*32,'name':'Iran','source':'127.0.0.1'}
        with self.assertRaisesRegex(ValueError,'another installation'):
            self.agent.telemetry(pair,{'config_hash':'b'*64,'probes':[]})
        with self.assertRaisesRegex(ValueError,'unknown probe'):
            self.agent.telemetry(pair,{'config_hash':digest('1'*64),'probes':[{'path':'ssh','ok':True}]})
        with self.assertRaisesRegex(ValueError,'service observations'):
            self.agent.telemetry(pair,{'config_hash':digest('1'*64),'probes':[{'path':'frp-wss','ok':True,'services':{'unknown':True}}]})

    async def test_tls_pin_is_checked_before_pairing_body_is_sent(self):
        cert,key=self.root/'test.crt',self.root/'test.key'
        subprocess.run(['openssl','req','-x509','-newkey','ed25519','-nodes','-days','1','-subj','/CN=Test','-keyout',str(key),'-out',str(cert)],check=True,capture_output=True)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key)
        received=[]
        async def handle(request):received.append(await request.json());return web.json_response({'accepted':True})
        app=web.Application();app.router.add_post('/exchange',handle)
        server=TestServer(app,scheme='https');await server.start_server(ssl=context)
        profile={'host':'127.0.0.1','agent_port':server.port,'agent_fingerprint':hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()}
        try:
            with self.assertRaises(ServerFingerprintMismatch):await peer_request({**profile,'agent_fingerprint':'b'*64},'/exchange',{'token':'private'})
            self.assertEqual(received,[])
            await peer_request(profile,'/exchange',{'token':'private'});self.assertEqual(received,[{'token':'private'}])
        finally:await server.close()

    async def test_foreign_health_never_conflates_active_unit_with_live_tunnel(self):
        store=Store(self.root/'state.sqlite')
        config=load_config(self.live);config['panel']={};config['state_db']=str(self.root/'state.sqlite')
        stamp=time.time();telemetry={'time':stamp,'config_hash':digest(config['health_key']),'probes':[{'path':'frp-wss','ok':True,'latency_ms':2,'services':{'app':True}}]}
        units=[{'unit':'donino-link-frp-wss.service','active':True,'state':'active','pid':1},{'unit':'donino-link-framed.service','active':True,'state':'active','pid':2}]
        def read(path,default=None):
            if str(path).endswith('install.json'):return {'units':['donino-link-frp-wss.service']}
            if str(path).endswith('peer-observations.json'):return telemetry
            return default
        try:
            with patch('donino_link.foreign.read_json',side_effect=read),patch('donino_link.foreign.unit_status',return_value=units),patch('donino_link.foreign.target_status',new=AsyncMock(return_value=True)):
                monitor=ForeignMonitor(config,store);await monitor.collect();self.assertTrue(monitor.snapshot()['paths'][0]['healthy'])
                units[1]['active']=False;await monitor.collect();self.assertFalse(monitor.snapshot()['paths'][0]['healthy']);units[1]['active']=True
                telemetry['time']=stamp-46;await monitor.collect();self.assertFalse(monitor.snapshot()['paths'][0]['healthy']);self.assertEqual(monitor.snapshot()['paths'][0]['observation'],'unknown')
                telemetry.update(time=stamp,config_hash='wrong');await monitor.collect();self.assertFalse(monitor.snapshot()['paths'][0]['healthy'])
                telemetry['config_hash']=digest(config['health_key']);units[0].update(active=False,state='inactive');await monitor.collect();self.assertFalse(monitor.snapshot()['paths'][0]['healthy'])
                self.assertIsNone(monitor.snapshot()['metrics'])
        finally:store.close()


class BootstrapTests(unittest.TestCase):
    def test_roles_start_without_tunnels_and_foreign_panel_requires_explicit_http(self):
        with tempfile.TemporaryDirectory() as tmp,patch('donino_link.bootstrap.stable_auth',return_value={'credentials_file':'/private/admin.json','api_token_file':'/private/token'}):
            iran=make_bootstrap(Path(tmp)/'iran','iran','192.0.2.10','password-test-123')
            foreign=make_bootstrap(Path(tmp)/'foreign','foreign','198.51.100.20','password-test-123')
            self.assertEqual(iran['services'],[]);self.assertEqual(iran['paths'],[]);self.assertEqual(foreign['targets'],{})
            manifest=json.loads((Path(tmp)/'foreign/install.json').read_text());self.assertEqual(manifest['engines'],[]);self.assertIn(9444,manifest['public_ports']['tcp'])
            iran['bootstrap']=False;atomic_json(Path(tmp)/'iran/node.json',iran)
            with self.assertRaises(ValueError):load_config(Path(tmp)/'iran/node.json')
            foreign['panel']['allow_insecure_http']=False;atomic_json(Path(tmp)/'foreign/node.json',foreign)
            with self.assertRaises(ValueError):load_config(Path(tmp)/'foreign/node.json')

    def test_bootstrap_ports_cannot_collide(self):
        with tempfile.TemporaryDirectory() as tmp,patch('donino_link.bootstrap.stable_auth'):
            for port in [9444,19090]:
                with self.assertRaises(ValueError):make_bootstrap(Path(tmp)/str(port),'foreign','198.51.100.20','password-test-123',panel_port=port)


class SSHAuthorizationTests(unittest.TestCase):
    def test_reload_failure_does_not_restore_revoked_key_or_grant_new_key(self):
        from donino_link.peer import ssh_rules
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);drop=root/'sshd.conf';keys=root/'authorized_keys'
            subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(root/'identity')],check=True)
            pub=(root/'identity.pub').read_text().strip()
            old={'id':'a'*32,'source':'192.0.2.10','public_key':pub,'revoked':False}
            new={**old,'id':'b'*32}
            with patch('donino_link.peer.SSH_DROPIN',drop),patch('donino_link.peer.subprocess.run',return_value=subprocess.CompletedProcess([],0)):
                ssh_rules(root,[old])
            original_drop=drop.read_text()
            with patch('donino_link.peer.SSH_DROPIN',drop),patch('donino_link.peer.subprocess.run',side_effect=subprocess.CalledProcessError(1,['systemctl'])):
                with self.assertRaises(subprocess.CalledProcessError):ssh_rules(root,[{**old,'revoked':True},new])
            self.assertEqual(keys.read_text().strip(),'')
            self.assertEqual(drop.read_text(),original_drop)
            self.assertEqual(keys.stat().st_mode&0o777,0o600)
