import asyncio
import base64
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from aiohttp.test_utils import TestClient, TestServer
from donino_link.panel import password_record
from donino_link.config import atomic_json
from donino_link.provision import Worker, Coordinator, CommandFailure, application, pinned_line
from donino_link.preflight import conflicts
from test_core import configuration


class Recorder:
    def __init__(self, fail=None): self.calls=[]; self.fail=fail
    def run(self, args, data=None, timeout=1800):
        self.calls.append(args)
        if self.fail and self.fail(args): raise CommandFailure(1)
        return ''


class ProvisionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.root=Path(self.tmp.name)
        self.live=self.root/'node.json'; self.config=configuration(self.root)
        atomic_json(self.live,self.config)
        atomic_json(self.root/'admin.json',password_record('integration-test-password'));(self.root/'api-token').write_text('test-api-token')
        self.w=Worker(self.root/'control',self.live)
        self.profile={'id':'a'*32,'name':'foreign','host':'198.51.100.20','port':2222,'fingerprint':'SHA256:'+'a'*43}
        atomic_json(self.w.root/'profiles.json',[self.profile]); (self.w.root/'hosts'/self.profile['id']).write_text('fixture')
        self.client=TestClient(TestServer(application(self.w)));await self.client.start_server()
    async def asyncTearDown(self): await self.client.close();self.tmp.cleanup()
    def spec(self):return {'profile_id':'a'*32,'iran':'192.0.2.10','services':[{'id':'web','listen':'0.0.0.0:443','target':'127.0.0.1:8443'}],'transports':['frp-wss']}

    async def test_pin_requires_independently_matching_key(self):
        raw=b'real-host-key';key=base64.b64encode(raw).decode();pin='SHA256:'+base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip('=')
        self.assertEqual(pinned_line('evil-label ssh-ed25519 '+key,'example.com',2222,pin),'[example.com]:2222 ssh-ed25519 '+key+'\n')
        with self.assertRaises(ValueError):pinned_line('host ssh-ed25519 '+key,'example.com',22,'SHA256:'+'a'*43)

    async def test_preview_freezes_bundle_and_preserves_authentication_and_listener(self):
        self.config['panel'].update(listen='0.0.0.0:18090',allow_insecure_http=True);atomic_json(self.live,self.config)
        p=self.w.preview(self.spec());node=json.loads((self.w.root/'plans'/p['id']/'iran/node.json').read_text())
        self.assertEqual(node['panel'],self.config['panel'])
        self.assertEqual((self.w.root/'plans'/p['id']/'iran/admin.json').read_bytes(),Path(self.config['panel']['credentials_file']).read_bytes())
        self.assertNotIn('health_key',json.dumps(p));self.assertNotIn('PRIVATE KEY',json.dumps(self.w.state()))
        self.assertEqual(self.w.identity.stat().st_mode&0o777,0o600)
        self.assertEqual(self.w.root.stat().st_mode&0o777,0o700)

    async def test_reject_arbitrary_commands_paths_and_unreviewed_start(self):
        response=await self.client.post('/preview',json={**self.spec(),'command':'touch /tmp/evil'})
        self.assertEqual(response.status,400)
        response=await self.client.post('/start',json={'plan_id':'../../etc','confirm_replace':True});self.assertEqual(response.status,400)
        p=self.w.preview(self.spec())
        response=await self.client.post('/start',json={'plan_id':p['id'],'confirm_replace':False});self.assertEqual(response.status,400)
        self.assertFalse(self.w.busy)

    async def test_live_change_invalidates_review_and_concurrent_job_is_rejected(self):
        p=self.w.preview(self.spec());self.config['policy']['failures']=4;atomic_json(self.live,self.config)
        with self.assertRaisesRegex(ValueError,'changed'):await self.w.start({'plan_id':p['id'],'confirm_replace':True})
        self.w.busy=True
        with self.assertRaisesRegex(ValueError,'already running'):self.w.preview(self.spec())
        with self.assertRaisesRegex(ValueError,'already running'):await self.w.start({'plan_id':p['id'],'confirm_replace':True})
        self.w.busy=False

    async def test_partial_activation_rolls_back_iran_then_foreign_with_release_guard(self):
        jid='b'*32;(self.w.root/'jobs'/jid).mkdir()
        job={'id':jid,'release':'/opt/donino-link/releases/control-'+jid,'activated':['foreign'],'activating':'iran','events':[],'status':'running'}
        runner=Recorder();Coordinator(self.w,runner).rollback(job,self.profile)
        self.assertEqual(runner.calls[0][:2],['bash',job['release']+'/scripts/rollback.sh'])
        self.assertEqual(runner.calls[0][-1],'--if-current')
        self.assertIn('--if-current',runner.calls[1][-1]);self.assertIn('-p',runner.calls[1]);self.assertIn('2222',runner.calls[1])
        self.assertEqual([e['stage'] for e in job['events'] if e['status']=='done'],['rollback-iran','rollback-foreign'])

    async def test_rollback_failure_is_not_reported_as_recovered(self):
        jid='c'*32;(self.w.root/'jobs'/jid).mkdir()
        job={'id':jid,'release':'/opt/donino-link/releases/control-'+jid,'activated':['foreign','iran'],'activating':None,'events':[],'status':'running'}
        runner=Recorder(fail=lambda args:args[0]=='ssh');Coordinator(self.w,runner).rollback(job,self.profile)
        self.assertEqual(job['status'],'rollback_failed');self.assertEqual(job['events'][-1]['status'],'failed')

    async def test_interrupted_job_survives_new_worker_and_is_recovered(self):
        jid='d'*32;(self.w.root/'jobs'/jid).mkdir();pid='e'*32;(self.w.root/'plans'/pid).mkdir()
        atomic_json(self.w.root/'plans'/pid/'control.json',{'profile_id':'a'*32})
        job={'id':jid,'plan_id':pid,'release':'/opt/donino-link/releases/control-'+jid,'activated':['foreign','iran'],'activating':None,'events':[],'status':'running','created':1,'probes':[]}
        self.w.save_job(job)
        restored=Worker(self.w.root,self.live,runner_factory=lambda log:Recorder())
        await restored.recover();state=restored.state()
        self.assertEqual(state['jobs'][0]['status'],'interrupted');self.assertFalse(restored.busy)
        self.assertEqual([e['stage'] for e in state['jobs'][0]['events'] if e['status']=='done'],['rollback-iran','rollback-foreign'])

    async def test_two_nodes_prepare_before_activation_and_all_paths_must_pass(self):
        p=self.w.preview(self.spec());runner=Recorder();self.w.runner_factory=lambda log:runner
        async def good(config):return [{'path':'frp-wss','ok':True,'latency_ms':1,'services':{'web':True}}]
        with patch('donino_link.cli.doctor',good),patch('donino_link.provision.load_config',lambda path:json.loads((self.w.root/'plans'/p['id']/'iran/node.json').read_text())):
            job=await self.w.start({'plan_id':p['id'],'confirm_replace':True});await self.w.task
        self.assertEqual(job['status'],'succeeded');self.assertEqual(job['activated'],['foreign','iran'])
        modes=[('--prepare' if '--prepare' in ' '.join(a) else '--activate') for a in runner.calls if '--prepare' in ' '.join(a) or '--activate' in ' '.join(a)]
        self.assertEqual(modes,['--prepare','--prepare','--activate','--activate'])
        # A TCP origin failure must roll back even when the signed carrier probe works.
        p=self.w.preview(self.spec());runner.calls=[]
        async def bad(config):return [{'path':'frp-wss','ok':True,'services':{'web':False}}]
        with patch('donino_link.cli.doctor',bad),patch('donino_link.provision.time.sleep'),patch('donino_link.provision.load_config',lambda path:json.loads((self.w.root/'plans'/p['id']/'iran/node.json').read_text())):
            job=await self.w.start({'plan_id':p['id'],'confirm_replace':True});await self.w.task
        self.assertEqual(job['status'],'failed')
        self.assertEqual([e['stage'] for e in job['events'] if e['stage'].startswith('rollback') and e['status']=='done'],['rollback-iran','rollback-foreign'])

    async def test_port_collision_ignores_only_owned_processes(self):
        rows='tcp LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=111,fd=5))\ntcp LISTEN 0 4096 127.0.0.1:30000 0.0.0.0:* users:(("frps",pid=222,fd=4))\nudp UNCONN 0 0 *:24444 *:*'
        wanted=[{'protocol':'tcp','port':443},{'protocol':'tcp','port':30000},{'protocol':'udp','port':24444}]
        self.assertEqual(conflicts(rows,wanted,lambda pid:pid==222),['tcp:443','udp:24444'])

if __name__=='__main__':unittest.main()
