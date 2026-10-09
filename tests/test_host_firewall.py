import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from donino_link.config import atomic_json
from donino_link.host_firewall import ports_spec,apply,remove

class HostFirewallTests(unittest.TestCase):
    def test_ports_are_scoped_validated_and_deduplicated(self):
        self.assertEqual(ports_spec({'tcp':[8090,443,443],'udp':[24444]}),'443,8090/tcp|24444/udp')
        for ports in [{'tcp':['443'],'udp':[]},{'tcp':[True],'udp':[]},{'tcp':[0],'udp':[]},{'tcp':[],'udp':[],'command':'reset'}]:
            with self.assertRaises(ValueError):ports_spec(ports)

    def test_active_ufw_gets_unique_profile_and_rollback_removes_only_that_app(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);node=root/'node';node.mkdir();release=root/'release';release.mkdir();profiles=root/'apps';profiles.mkdir()
            atomic_json(node/'install.json',{'open_ufw':True,'public_ports':{'tcp':[443,8090],'udp':[24444]}})
            tag='control-'+'a'*32;app='Donino-'+tag;calls=[]
            def command(*args):
                calls.append(args)
                if args==('status',):return 'Status: active\n'
                if args==('show','added'):return "ufw allow 22/tcp\nufw allow '"+app+"' comment '"+app+"'\n"
                return ''
            with patch('donino_link.host_firewall.shutil.which',return_value='/usr/sbin/ufw'),patch('donino_link.host_firewall.command',command):
                result=apply(node,release,tag,profiles);self.assertEqual(result['mode'],'ufw')
                self.assertIn('ports=443,8090/tcp|24444/udp',(profiles/app).read_text())
                remove(release,profiles)
            self.assertIn(('allow',app,'comment',app),calls);self.assertIn(('--force','delete','allow',app),calls)
            self.assertFalse((profiles/app).exists());self.assertFalse(any('reset' in a or 'disable' in a or '22/tcp' in a for a in calls))

    def test_inactive_or_absent_ufw_is_reported_without_enabling(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);node=root/'node';node.mkdir();atomic_json(node/'install.json',{'open_ufw':True,'public_ports':{'tcp':[443],'udp':[]}})
            with patch('donino_link.host_firewall.shutil.which',return_value=None):result=apply(node,root,'control-'+'a'*32)
            self.assertEqual(result['mode'],'manual');self.assertFalse(result['changed'])

    def test_no_opt_in_means_no_firewall_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);atomic_json(root/'install.json',{'open_ufw':False})
            with patch('donino_link.host_firewall.command') as command:self.assertEqual(apply(root,root,'control-'+'a'*32)['mode'],'manual');command.assert_not_called()
