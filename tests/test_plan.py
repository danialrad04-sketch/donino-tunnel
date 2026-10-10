import json
import tempfile
import unittest
from pathlib import Path
from donino_link.plan import make_plan,renew_plan
from donino_link.config import load_config
from donino_link.deploy import build_payload,deploy


class PlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory()
        cls.root=Path(cls.temp.name)
        cls.plan=cls.root/'private-plan'
        cls.services=[{'id':'web','listen':'0.0.0.0:443','target':'127.0.0.1:8443'}]
        make_plan(cls.plan,'192.0.2.10','198.51.100.20',cls.services,['frp-wss','frp-quic','paqet','backpack-wss'],'private-test-password',True)

    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()

    def test_generated_node_configs_validate(self):
        self.assertEqual(load_config(self.plan/'iran/node.json')['role'],'iran')
        self.assertEqual(load_config(self.plan/'foreign/node.json')['role'],'foreign')

    def test_node_payload_excludes_other_node_and_ca_key(self):
        stage=self.root/'stage'
        build_payload(self.plan/'foreign',stage)
        self.assertTrue((stage/'scripts/install-node.sh').exists())
        self.assertTrue((stage/'node/certs/client.key').exists())
        self.assertFalse((stage/'node/certs/server.key').exists())
        self.assertFalse(any(p.name=='ca.key' for p in stage.rglob('*')))
        self.assertFalse((stage/'node/admin.json').exists())

    def test_dry_run_has_no_server_mutations(self):
        result=deploy(self.plan,'root@192.0.2.10','root@198.51.100.20',dry_run=True)
        self.assertEqual(result['order'],['foreign','iran'])
        self.assertEqual(result['host_key_verification'],'strict')

    def test_paqet_has_authenticated_encryption_and_auto_network(self):
        config=json.loads((self.plan/'iran/transports/paqet.yaml').read_text())
        self.assertEqual(config['transport']['kcp']['block'],'aes-128-gcm')
        self.assertEqual(config['network']['interface'],'AUTO')
        self.assertEqual(config['transport']['kcp']['mtu'],1150)

    def test_front_is_public_but_frps_wss_is_loopback(self):
        config=(self.plan/'iran/transports/frp-wss.toml').read_text()
        self.assertIn('bindAddr = "127.0.0.1"',config)
        self.assertNotIn('transport.tls.trustedCaFile',config)
        unit=(self.plan/'iran/units/donino-link-frp-wss-front.service').read_text()
        self.assertIn('--ca /etc/donino-link/current/certs/ca.crt',unit)

    def test_health_service_name_is_reserved_for_authenticated_probe(self):
        with self.assertRaises(ValueError):
            make_plan(self.root/'reserved-health','192.0.2.10','198.51.100.20',[{'id':'health','listen':'0.0.0.0:443','target':'127.0.0.1:8443'}],['frp-wss'],'private-test-password')
        self.assertFalse((self.root/'reserved-health').exists())

    def test_experimental_is_explicit(self):
        with self.assertRaises(ValueError):
            make_plan(self.root/'forbidden','192.0.2.10','198.51.100.20',self.services,['paqet'],'private-test-password')

    def test_renewal_preserves_ca_and_tokens(self):
        ca=(self.plan/'ca/ca.crt').read_bytes()
        health=json.loads((self.plan/'iran/node.json').read_text())['health_key']
        renew_plan(self.plan)
        self.assertEqual(ca,(self.plan/'ca/ca.crt').read_bytes())
        self.assertEqual(health,json.loads((self.plan/'iran/node.json').read_text())['health_key'])

    def test_browser_plan_maps_owned_origin_and_renewal_pin(self):
        plan=self.root/'browser-plan'
        make_plan(plan,'192.0.2.10','outside.example',self.services,['browser-wss'],'private-test-password',True)
        iran=json.loads((plan/'iran/transports/browser-wss.json').read_text())
        foreign=json.loads((plan/'foreign/transports/browser-wss.json').read_text())
        self.assertEqual(iran['origin'],'https://outside.example:24443')
        self.assertEqual(foreign['targets']['web'],'127.0.0.1:8443')
        self.assertEqual(json.loads((plan/'iran/install.json').read_text())['engines'],[])
        self.assertNotIn('test_no_sandbox',iran)
        self.assertEqual(json.loads((plan/'plan.json').read_text())['firewall']['foreign']['tcp'],[24443])
        old=iran['spki']
        renew_plan(plan)
        renewed=json.loads((plan/'iran/transports/browser-wss.json').read_text())
        self.assertNotEqual(old,renewed['spki'])
        self.assertEqual(iran['token'],renewed['token'])

    def test_public_browser_443_is_independent_of_iran_443(self):
        plan=self.root/'browser-public-plan'
        summary=make_plan(plan,'192.0.2.10','outside.example',self.services,['frp-wss','browser-wss'],'private-test-password',True,browser_port=443)
        self.assertEqual(summary['firewall']['foreign']['tcp'],[443])
        iran=json.loads((plan/'iran/transports/browser-wss.json').read_text())
        self.assertEqual(iran['origin'],'https://outside.example')
        with self.assertRaises(ValueError):
            make_plan(self.root/'port-conflict','192.0.2.10','outside.example',self.services,['browser-wss'],'private-test-password',True,browser_port=8443)

    def test_mux_plan_is_builtin_mutual_tls_and_renewable(self):
        plan=self.root/'mux-plan'
        summary=make_plan(plan,'192.0.2.10','outside.example',self.services,['donino-mux'],'private-test-password',True)
        iran=json.loads((plan/'iran/transports/donino-mux.json').read_text())
        foreign=json.loads((plan/'foreign/transports/donino-mux.json').read_text())
        self.assertEqual(iran['url'],'wss://outside.example:24443/link')
        self.assertEqual(foreign['targets']['web'],'127.0.0.1:8443')
        self.assertEqual(summary['firewall']['foreign']['tcp'],[24443])
        self.assertNotIn(24443,summary['firewall']['iran']['tcp'])
        for role in ['iran','foreign']:
            install=json.loads((plan/role/'install.json').read_text())
            self.assertEqual(install['engines'],[]);self.assertFalse(install['browser'])
            self.assertIn('-m donino_link.mux',(plan/role/'units/donino-link-donino-mux.service').read_text())
            self.assertFalse((plan/role/'units/donino-link-framed.service').exists())
        self.assertNotEqual((plan/'iran/certs/mux-client.key').read_bytes(),(plan/'foreign/certs/client.key').read_bytes())
        self.assertFalse((plan/'foreign/certs/mux-client.key').exists())
        self.assertFalse((plan/'iran/certs/client.key').exists())
        old_ca=(plan/'ca/ca.crt').read_bytes();old_client=(plan/'iran/certs/mux-client.crt').read_bytes()
        renew_plan(plan)
        self.assertEqual(old_ca,(plan/'ca/ca.crt').read_bytes())
        self.assertNotEqual(old_client,(plan/'iran/certs/mux-client.crt').read_bytes())
        self.assertEqual((plan/'iran/certs/mux-client.crt').read_bytes(),(plan/'ca/mux-client.crt').read_bytes())
        self.assertEqual((plan/'foreign/certs/browser.crt').read_bytes(),(plan/'ca/browser.crt').read_bytes())
        stage=self.root/'mux-stage';build_payload(plan/'iran',stage)
        self.assertTrue((stage/'node/certs/mux-client.key').exists())
        self.assertFalse(any(p.name in ('ca.key','browser.key','client.key') for p in stage.rglob('*')))

    def test_continuum_plan_preserves_mux_and_installs_both_roles(self):
        plan=self.root/'continuum-plan'
        summary=make_plan(plan,'192.0.2.10','outside.example',self.services,['donino-mux','donino-continuum'],'private-test-password',True)
        iran=json.loads((plan/'iran/transports/donino-continuum.json').read_text())
        foreign=json.loads((plan/'foreign/transports/donino-continuum.json').read_text())
        self.assertEqual(iran['url'],'wss://outside.example:24444/continuum')
        self.assertEqual(foreign['targets']['web'],'127.0.0.1:8443')
        self.assertEqual(summary['firewall']['foreign']['tcp'],[24443,24444])
        for role in ['iran','foreign']:
            install=json.loads((plan/role/'install.json').read_text())
            self.assertEqual(install['engines'],[])
            self.assertIn('-m donino_link.continuum',(plan/role/'units/donino-link-donino-continuum.service').read_text())
            self.assertIn('-m donino_link.mux',(plan/role/'units/donino-link-donino-mux.service').read_text())
            self.assertFalse((plan/role/'units/donino-link-framed.service').exists())
        renew_plan(plan)
        self.assertEqual((plan/'iran/certs/mux-client.crt').read_bytes(),(plan/'ca/mux-client.crt').read_bytes())
        stage=self.root/'continuum-stage';build_payload(plan/'foreign',stage)
        self.assertEqual(len(list(stage.rglob('continuum.py'))),1)

    def test_packaged_metadata_is_current(self):
        root=Path(__file__).resolve().parent.parent
        self.assertEqual((root/'pyproject.toml').read_bytes(),(root/'donino_link/resources/pyproject.toml').read_bytes())


if __name__=='__main__':unittest.main()
