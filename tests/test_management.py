"""Real TLS between controller/agent; no SSH or user VPS is used here."""
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

from aiohttp import ClientConnectionError, ServerFingerprintMismatch, web
from aiohttp.test_utils import TestServer

from donino_link.config import atomic_json
from donino_link.management import node_files, remote_operation, runtime_digest, validated_node
from donino_link.peer import ForeignAgent, application, digest, peer_request
from donino_link.plan import make_plan, TRANSPORTS
from donino_link.provision import Worker, read_json


class NodeBundleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.spec = {'iran':'192.0.2.10', 'foreign':'198.51.100.20',
                    'services':[{'id':'app','listen':'0.0.0.0:18080','target':'127.0.0.1:18081'}],
                    'transports':list(TRANSPORTS),'experimental':True,'open_ufw':False}
        make_plan(cls.root/'plan',cls.spec['iran'],cls.spec['foreign'],cls.spec['services'],
                  cls.spec['transports'],'management-fixture-password',experimental=True)
        manifest = read_json(cls.root/'plan/foreign/install.json');manifest['open_ufw']=False
        atomic_json(cls.root/'plan/foreign/install.json',manifest)
        cls.files = node_files(cls.root/'plan/foreign')

    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()

    def validate(self, files, spec=None):
        with tempfile.TemporaryDirectory() as temp:
            return validated_node(Path(temp),spec or self.spec,files)

    def test_all_eight_foreign_transports_are_reconstructed_from_local_code(self):
        self.validate(self.files)

    def test_no_executable_archive_path_ca_key_or_extra_file_can_be_uploaded(self):
        for name in ('scripts/install-node.sh','../../escape','certs/ca.key','units/evil.service'):
            with self.subTest(name=name),self.assertRaises(ValueError):
                self.validate({**self.files,name:'malicious'})

    def test_systemd_and_transport_commands_are_not_accepted_as_data(self):
        for name, value in (
            ('units/donino-link.service',self.files['units/donino-link.service'].replace('User=donino-link','User=root')),
            ('transports/frp-wss.toml',self.files['transports/frp-wss.toml']+'\n[plugin]\ntype="unix_domain_socket"\n'),
            ('node.json',self.files['node.json'].replace('127.0.0.1:18081','169.254.169.254:80')),
        ):
            with self.subTest(name=name),self.assertRaises(ValueError):
                self.validate({**self.files,name:value})

    def test_mismatched_manifest_engine_url_and_oversized_body_are_rejected(self):
        altered=json.loads(self.files['install.json']);altered['download_url']='https://example.com/evil'
        with self.assertRaises(ValueError):self.validate({**self.files,'install.json':json.dumps(altered)})
        with self.assertRaises(ValueError):self.validate({**self.files,'node.json':'x'*262145})


class RecordingRunner:
    def __init__(self):self.calls=[]
    def run(self,args,data=None,timeout=1800):
        if args[0] in ('ssh','scp','ssh-keyscan'):raise AssertionError('SSH was used')
        self.calls.append(list(args));return ''


class ManagementTLSTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.live=self.root/'foreign-node.json'
        atomic_json(self.live,{'schema':1,'role':'foreign','health_key':'1'*64,
                             'health_listen':'127.0.0.1:19090','targets':{},
                             'panel':{'listen':'0.0.0.0:8091','allow_insecure_http':True}})
        self.agent=ForeignAgent(self.root/'agent',self.live,{'fingerprint':'a'*64,'port':9444,'ssh_port':22},
                                lambda *args: self.fail('SSH authorization was modified'))
        self.cert,self.key=self.root/'agent.crt',self.root/'agent.key'
        subprocess.run(['openssl','req','-x509','-newkey','ed25519','-nodes','-days','1',
                        '-subj','/CN=fixture','-keyout',str(self.key),'-out',str(self.cert)],check=True,capture_output=True)
        self.pin=hashlib.sha256(ssl.PEM_cert_to_DER_cert(self.cert.read_text())).hexdigest()
        self.agent.fingerprint=self.pin
        tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.load_cert_chain(self.cert,self.key)
        self.server=TestServer(application(self.agent,True),scheme='https');await self.server.start_server(ssl=tls)
        controller=self.root/'iran-node.json'
        atomic_json(controller,{'schema':1,'role':'iran','health_key':'2'*64,'services':[],'paths':[],
                                'bootstrap':True,'panel':{'listen':'127.0.0.1:8090'}})
        self.worker=Worker(self.root/'controller',controller,allow_private=True)

    async def asyncTearDown(self):
        await asyncio.gather(*list(self.agent.tasks),return_exceptions=True)
        await self.server.close();self.temp.cleanup()

    async def pair(self):
        code=self.agent.pairing_code()['code']
        with patch.object(self.worker,'add_profile',side_effect=AssertionError('SSH profile was created')):
            result=await asyncio.to_thread(self.worker.pair,{'name':'Foreign fixture','host':'127.0.0.1',
                                                            'agent_port':self.server.port,'code':code})
        return self.worker.profile(result['id'])

    async def test_paired_backend_routes_require_auth_and_never_return_root_receipts(self):
        profile=await self.pair()
        for route in ('/vpn-backend','/vpn-backend-api'):
            with self.assertRaises(ValueError):
                await peer_request({**profile,'agent_token':'wrong'},route,{})
        class BackendFixture:
            def install(self,body):
                if body != {'confirm_install':True}:raise ValueError('confirm required')
                return {'token':'PRIVATE-VENDOR-TOKEN'}
            def status(self):return {'installed':True,'active':True}
        with patch('donino_link.vpn_backend.Backend',return_value=BackendFixture()):
            result=await peer_request(profile,'/vpn-backend',{'operation':'install','confirm_install':True})
            self.assertEqual(result,{'installed':True,'active':True})
            self.assertNotIn('PRIVATE-VENDOR-TOKEN',json.dumps(result))
        with patch('donino_link.vpn_bridge.local_api',AsyncMock(return_value={'success':True,'obj':[]})) as call:
            await peer_request(profile,'/vpn-backend-api',{'method':'GET','route':'/panel/api/clients/list'})
            call.assert_awaited_once()
        self.agent.revoke(self.agent.pairs()[0]['id'])
        with self.assertRaises(ValueError):
            await peer_request(profile,'/vpn-backend-api',{'method':'GET','route':'/panel/api/clients/list'})

    async def test_pairing_and_roundtrip_need_no_root_ssh_login(self):
        profile=await self.pair()
        self.assertEqual(profile['management'],'https-v1');self.assertNotIn('port',profile)
        result=await asyncio.to_thread(self.worker.check_connection,{'profile_id':profile['id']})
        self.assertTrue(result['ok']);self.assertTrue(result['runtime_match'])
        self.assertFalse(list(self.agent.root.glob('check-*')))
        self.assertFalse((self.agent.root/'authorized_keys').exists())
        public=json.dumps(self.worker.state());self.assertNotIn(profile['agent_token'],public)

    async def test_tls_pin_failure_and_revocation_do_not_downgrade_to_ssh(self):
        profile=await self.pair()
        with self.assertRaises(ServerFingerprintMismatch):
            await peer_request({**profile,'agent_fingerprint':'0'*64},'/connection',{})
        pair=self.agent.pairs()[0];self.agent.revoke(pair['id'])
        with self.assertRaisesRegex(ValueError,'authentication failed'):
            await peer_request(profile,'/connection',{})

    async def test_unauthorized_mutations_and_unknown_commands_are_rejected(self):
        profile=await self.pair()
        for route in ('/install','/install-status','/node-action','/node-imported-action'):
            with self.subTest(route=route),self.assertRaises(ValueError):
                await peer_request({**profile,'agent_token':'wrong'},route,{})
        with self.assertRaises(ValueError):
            await peer_request(profile,'/node-action',{'unit':'ssh.service','action':'stop'})
        with self.assertRaises(ValueError):
            await peer_request(profile,'/connection',{'command':'id'})

    async def test_service_control_reaches_foreign_agent_over_real_tls(self):
        profile=await self.pair()
        atomic_json(self.live.parent/'install.json',{'units':['donino-link-frp-wss.service']})
        with patch('donino_link.peer.subprocess.run',return_value=subprocess.CompletedProcess([],0)) as systemd:
            response=await self.worker.remote_action({'profile_id':profile['id'],'kind':'service',
                                                     'body':{'unit':'donino-link-frp-wss.service','action':'restart'}})
            await asyncio.gather(*list(self.agent.tasks))
        self.assertIn(response['status'],('running','succeeded'))
        self.assertEqual(read_json(self.agent.root/'actions.json')[0]['status'],'succeeded')
        self.assertEqual(systemd.call_args.args[0],['systemctl','restart','donino-link-frp-wss.service'])

    async def test_installation_receipt_survives_lost_response_without_duplicate_execution(self):
        profile=await self.pair();pair=self.agent.pairs()[0];job='b'*32
        self.agent.reserve(pair,{'job_id':job});runner=RecordingRunner();self.agent.management.runner_factory=lambda log:runner
        # A small legitimate plan, generated once with real certificates.
        plan=self.root/'plan'
        spec={'iran':'192.0.2.10','foreign':'198.51.100.20',
              'services':[{'id':'app','listen':'0.0.0.0:18080','target':'127.0.0.1:18081'}],
              'transports':['frp-wss'],'open_ufw':False}
        await asyncio.to_thread(make_plan,plan,spec['iran'],spec['foreign'],spec['services'],spec['transports'],'fixture-password-123')
        manifest=read_json(plan/'foreign/install.json');manifest['open_ufw']=False;atomic_json(plan/'foreign/install.json',manifest)
        files=node_files(plan/'foreign');lost=False
        real=peer_request
        async def lose_reply(*args,**kwargs):
            nonlocal lost
            result=await real(*args,**kwargs)
            if args[1]=='/install' and not lost:
                lost=True;raise ClientConnectionError('simulated response loss')
            return result
        with patch('donino_link.peer.peer_request',side_effect=lose_reply):
            result=await asyncio.to_thread(remote_operation,profile,job,'prepare',spec=spec,files=files,runtime_digest=runtime_digest())
        self.assertEqual(result['status'],'succeeded');self.assertEqual(len(runner.calls),1)
        result=await asyncio.to_thread(remote_operation,profile,job,'prepare',spec=spec,files=files,runtime_digest=runtime_digest())
        self.assertEqual(result['status'],'succeeded');self.assertEqual(len(runner.calls),1)
        with self.assertRaisesRegex(ValueError,'reused'):
            await peer_request(profile,'/install',{'job_id':job,'operation':'prepare','runtime_digest':runtime_digest(),
                                                  'spec':spec,'files':{**files,'node.json':'changed'}})
        for op in ('activate','rollback','cleanup'):
            result=await asyncio.to_thread(remote_operation,profile,job,op)
            self.assertEqual(result['status'],'succeeded')
        self.assertFalse(any(c[0]=='ssh' for c in runner.calls))
        self.assertFalse((self.agent.management.root/pair['id']/job/'payload').exists())
        self.agent.release(pair,{'job_id':job})

    async def test_lease_runtime_and_peer_boundaries(self):
        profile=await self.pair()
        with self.assertRaisesRegex(ValueError,'lease'):
            await peer_request(profile,'/install',{'job_id':'a'*32,'operation':'activate'})
        with self.assertRaisesRegex(ValueError,'runtimes differ'):
            await peer_request(profile,'/install',{'job_id':'a'*32,'operation':'prepare','runtime_digest':'wrong','spec':{},'files':{}})
        with self.assertRaises(ValueError):
            await peer_request(profile,'/install',{'job_id':'../../root','operation':'cleanup'})
        with self.assertRaises(ValueError):
            await peer_request(profile,'/install',{'job_id':'a'*32,'operation':'bash'})
