import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from donino_link import paqet, udp_health
from donino_link.config import atomic_json, load_config
from donino_link.network import prepare_paqet
from donino_link.plan import make_plan
from donino_link.raw_rules import change
from donino_link.provision import Worker


class PaqetOptionsTests(unittest.TestCase):
    def test_every_upstream_mode_and_block_is_typed(self):
        for mode in paqet.MODES:
            for block in paqet.BLOCKS:
                o=paqet.options({'kcp':{'mode':mode,'block':block},'allow_insecure':block in ('none','null')})
                self.assertEqual(o['kcp']['block'],block)
                if mode=='manual':self.assertEqual(o['kcp']['interval'],10)

    def test_unsafe_invalid_and_unknown_settings_are_rejected(self):
        bad=[{'kcp':{'block':'none'}},{'kcp':{'block':'null'}},{'conn':True},{'conn':0},{'command':'sh'},
             {'kcp':{'tcpbuf':4096}},{'kcp':{'mtu':1501}},{'kcp':{'dshard':10}},
             {'kcp':{'dshard':128,'pshard':128}},{'kcp':{'streambuf':1}},
             {'kcp':{'smuxkalive':10,'smuxktimeout':8}},{'kcp':{'wdelay':'true'}},
             {'network':{'iran':{'source_port':33435}}},{'network':{'foreign':{'source_port':0}}},
             {'network':{'iran':{'interface':'eth0;sh'}}},{'local_flag':['PA;sh']},
             {'network':{'iran':{'ipv6':'2001:db8::1'}}},{'key':'short'}, {'socks5':None}, {'forwards':{}},
             {'socks5':[{'listen':'0.0.0.0:1080'}]}, {'socks5':[{'listen':'127.0.0.1:1080','username':'u'}]},
             {'forwards':[{'listen':'0.0.0.0:8000','target':'example.com:9000','protocol':'udp'}]}]
        for value in bad:
            with self.subTest(value=value),self.assertRaises(ValueError):paqet.options(value)

    def test_credentials_are_private_and_duplicate_bindings_fail(self):
        o=paqet.options({'key':'a'*32,'socks5':[{'listen':'0.0.0.0:1080','username':'u','password':'sensitive'}]})
        public=paqet.safe_options(o)
        self.assertNotIn('a'*32,json.dumps(public));self.assertNotIn('sensitive',json.dumps(public))
        self.assertTrue(public['socks5'][0]['authenticated']);self.assertEqual(o['socks5'][0]['password'],'sensitive')
        with self.assertRaisesRegex(ValueError,'duplicate'):
            paqet.options({'forwards':[{'listen':'127.0.0.1:1080','target':'127.0.0.1:9000','protocol':'tcp'}], 'socks5':[{'listen':'127.0.0.1:1080'}]})


class PaqetPlanTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.settings={'conn':1,'key':'paqet-private-fixture-key-123456','kcp':{'mode':'manual','dshard':10,'pshard':3,'sndwnd':128,'rcvwnd':128},
                       'pcap_sockbuf':4194304,'local_flag':['PA'],'remote_flag':['PA'],
                       'network':{'iran':{'interface':'eth0','local_ip':'192.0.2.10','router_mac':'02:00:00:00:00:01','source_port':33435}},
                       'forwards':[{'listen':'0.0.0.0:18084','target':'127.0.0.1:18082','protocol':'udp'},
                                   {'listen':'127.0.0.1:18086','target':'127.0.0.1:18083','protocol':'tcp'}],
                       'socks5':[{'listen':'127.0.0.1:1080','username':'fixture','password':'socks-private-fixture'}]}
    def tearDown(self):self.tmp.cleanup()
    def plan(self,services=None,iran='192.0.2.10',foreign='198.51.100.20',settings=None):
        return make_plan(self.root/'plan',iran,foreign,services or [],['paqet'],'fixture-password-123',True,paqet_options=self.settings if settings is None else settings)

    def test_native_only_plan_has_signed_udp_health_and_private_settings(self):
        summary=self.plan();cfg=load_config(self.root/'plan/iran/node.json');server=load_config(self.root/'plan/foreign/node.json')
        self.assertTrue(cfg['native_only']);self.assertEqual(cfg['services'],[])
        self.assertEqual(cfg['paths'][0]['udp_health'],'127.0.0.1:30051');self.assertEqual(server['udp_health_listen'],'127.0.0.1:19091')
        private=json.loads((self.root/'plan/iran/transports/paqet.yaml').read_text())
        self.assertEqual(private['transport']['kcp']['key'],self.settings['key']);self.assertEqual(private['network']['tcp']['local_flag'],['PA'])
        self.assertEqual(private['network']['pcap']['sockbuf'],4194304)
        self.assertIn(18084,summary['firewall']['iran']['udp'])
        public=json.dumps(summary)+json.dumps(paqet.status(self.root/'plan/iran'))
        self.assertNotIn(self.settings['key'],public);self.assertNotIn('socks-private-fixture',public)
        install=json.loads((self.root/'plan/iran/install.json').read_text())
        self.assertIn({'protocol':'tcp','port':33435},install['listeners'])
        self.assertIn({'protocol':'udp','port':18084},install['listeners'])

    def test_udp_health_does_not_collide_with_user_forward(self):
        self.settings['forwards'][0]['listen']='0.0.0.0:30051'
        with self.assertRaisesRegex(ValueError,'UDP health'):self.plan()

    def test_native_empty_and_mixed_transports_are_not_silently_accepted(self):
        with self.assertRaises(ValueError):self.plan(settings={})
        with self.assertRaises(ValueError):make_plan(self.root/'mixed','192.0.2.10','198.51.100.20',[],['frp-wss','paqet'],'fixture-password-123',True,paqet_options=self.settings)

    def test_ipv6_raw_rules_and_plan_addresses(self):
        self.plan(iran='2001:db8::1',foreign='2001:db8::2',settings={**self.settings,'network':{}})
        cfg=json.loads((self.root/'plan/iran/transports/paqet.yaml').read_text())
        self.assertEqual(cfg['server']['addr'],'[2001:db8::2]:33434')
        with patch('donino_link.raw_rules.subprocess.run') as command:
            command.return_value.returncode=1
            change('apply','2001:db8::2',33434)
            self.assertTrue(all(call.args[0][0]=='ip6tables' for call in command.call_args_list))
        with self.assertRaises(ValueError):self.plan(iran='192.0.2.1',foreign='2001:db8::2')

    def test_network_override_checks_assigned_addresses_and_preserves_tuning(self):
        self.plan();node=self.root/'plan/iran'
        assigned=[{'addr_info':[{'local':'192.0.2.10'}]}]
        with patch('donino_link.network.command_json',return_value=assigned) as command,patch('donino_link.network.discover') as discover:
            prepare_paqet(node);discover.assert_not_called()
            self.assertEqual(command.call_args.args,('ip','-j','addr','show','dev','eth0'))
        cfg=json.loads((node/'transports/paqet.yaml').read_text())
        self.assertEqual(cfg['network']['ipv4']['addr'],'192.0.2.10:33435');self.assertEqual(cfg['network']['tcp']['local_flag'],['PA'])
        self.assertEqual(cfg['network']['pcap']['sockbuf'],4194304)
        with patch('donino_link.network.command_json',return_value=[]),self.assertRaisesRegex(ValueError,'not assigned'):prepare_paqet(node)

    def test_bounded_diagnostics_and_secret_redaction(self):
        self.plan();node=self.root/'plan/iran';binary=self.root/'fake-paqet'
        binary.write_text('#!/usr/bin/env python3\nprint("'+self.settings['key']+' socks-private-fixture")\nprint("x"*100000)\n');binary.chmod(0o700)
        result=paqet.diagnostic('version',node,str(binary))
        self.assertTrue(result['truncated']);self.assertLessEqual(len(result['output']),65536)
        self.assertNotIn(self.settings['key'],result['output']);self.assertNotIn('socks-private-fixture',result['output'])
        with self.assertRaises(ValueError):paqet.diagnostic('dump',node,str(binary))
        with self.assertRaises(ValueError):paqet.diagnostic('ping',self.root/'plan/foreign',str(binary))
        with self.assertRaises(ValueError):paqet.diagnostic('shell',node,str(binary))

    def test_worker_preserves_secrets_but_rejects_malformed_preservation(self):
        self.plan();live=self.root/'plan/iran/node.json';worker=Worker(self.root/'control',live)
        profile={'id':'a'*32,'name':'outside','host':'198.51.100.20','port':22,'fingerprint':'SHA256:'+'a'*43}
        atomic_json(worker.root/'profiles.json',[profile]);(worker.root/'hosts'/profile['id']).write_text('fixture')
        o=paqet.safe_options(self.settings)
        for row in o['socks5']:row.pop('authenticated')
        spec={'profile_id':profile['id'],'iran':'192.0.2.10','services':[],'transports':['paqet'],'experimental':True,'paqet_options':o,'paqet_keep_secrets':True}
        result=worker.validate_spec(spec)
        self.assertEqual(result['paqet_options']['key'],self.settings['key']);self.assertEqual(result['paqet_options']['socks5'][0]['password'],'socks-private-fixture')
        spec['paqet_options']={'socks5':None}
        with self.assertRaises(ValueError):worker.validate_spec(spec)


class UDPHealthTests(unittest.IsolatedAsyncioTestCase):
    async def test_signed_udp_roundtrip_and_wrong_key_timeout(self):
        transport,_=await asyncio.get_running_loop().create_datagram_endpoint(lambda:udp_health.Responder('1'*64),local_addr=('127.0.0.1',0))
        try:
            endpoint='127.0.0.1:'+str(transport.get_extra_info('sockname')[1])
            self.assertGreaterEqual(await udp_health.probe(endpoint,'1'*64),0)
            with self.assertRaises(asyncio.TimeoutError):await udp_health.probe(endpoint,'2'*64,.1)
        finally:transport.close()

    async def test_invalid_packets_do_not_crash_or_receive_replies(self):
        sent=[];responder=udp_health.Responder('key');responder.connection_made(type('Transport',(),{'sendto':lambda self,*a:sent.append(a)})())
        for packet in [b'x'*513,b'[]',b'{}',b'null',b'\xff',b'{"nonce":1,"auth":true}',b'{"nonce":"'+b'a'*64+b'","auth":false}']:
            responder.datagram_received(packet,('127.0.0.1',1))
        self.assertEqual(sent,[])

if __name__=='__main__':unittest.main()
