import asyncio
import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import yaml
from donino_link.discovery import Inventory,read_config,safe,restore_secrets,validate_paqet,config_arg,known_engine,root_owned,bounded
from donino_link.config import atomic_json


def configuration():
    return {'role':'client','log':{'level':'warn'},'network':{'interface':'eth0','ipv4':{'addr':'192.0.2.1:0','router_mac':'02:00:00:00:00:01'}},
            'server':{'addr':'198.51.100.20:33434'},'transport':{'protocol':'kcp','conn':2,'kcp':{'mode':'normal','block':'aes-128-gcm','key':'private-fixture-key-123456789'}},
            'socks5':[{'listen':'127.0.0.1:1080','username':'a','password':'private-password-a'},{'listen':'127.0.0.1:1081','username':'b','password':'private-password-b'}],
            'forward':[{'listen':'0.0.0.0:8000','target':'127.0.0.1:8443','protocol':'tcp'}]}


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.file=self.root/'vendor-client.yaml';self.binary=self.root/'paqet_linux_amd64'
        self.file.write_text('# vendor configuration\n'+yaml.safe_dump(configuration()));self.file.chmod(0o600)
        self.binary.write_bytes(b'fixture');self.binary.chmod(0o755)
        self.inventory=Inventory(self.root,self.root/'node.json');self.unit='vendor-custom.service'
        self.commands=[];self.fail_restart=False
        # The unit fixture runs as the CI runner, while the systemd fixture
        # below verifies real root ownership. Preserve real file modes/IO here.
        self.permission_mock=patch('donino_link.discovery.root_owned',side_effect=lambda info:info.st_uid==os.geteuid() and not info.st_mode&0o022);self.permission_mock.start()
        self.mock=patch('donino_link.discovery.bounded',side_effect=self.command);self.mock.start()
    def tearDown(self):self.mock.stop();self.permission_mock.stop();self.tmp.cleanup()
    def command(self,argv,**kwargs):
        self.commands.append(argv)
        if argv[0]=='journalctl':return 0,json.dumps({'__CURSOR':'s=123;i=12;b=123','__REALTIME_TIMESTAMP':'123000','MESSAGE':'private-fixture-key-123456789 private-password-a'})+'\n',False
        if argv[1]=='list-unit-files':return 0,self.unit+' enabled\nssh.service enabled\n',False
        if argv[1]=='list-units':return 0,self.unit+' loaded active running\n',False
        if argv[1]=='show':return 0,'Id='+self.unit+'\nExecStart={ path='+str(self.binary)+' ; argv[]='+str(self.binary)+' run -c '+str(self.file)+' ; ignore_errors=no ; }\nMainPID=0\nActiveState=active\nUnitFileState=enabled\nMemoryCurrent=12345\nNRestarts=2\n',False
        if argv[1]=='restart' and self.fail_restart:
            self.fail_restart=False;return 1,'failed',False
        return 0,'',False
    def selected(self):
        return self.inventory.scan(True)['services'][0]

    def test_root_ownership_policy_rejects_nonroot_and_writable_files(self):
        from types import SimpleNamespace
        self.assertTrue(root_owned(SimpleNamespace(st_uid=0,st_mode=0o100600)))
        self.assertFalse(root_owned(SimpleNamespace(st_uid=1000,st_mode=0o100600)))
        self.assertFalse(root_owned(SimpleNamespace(st_uid=0,st_mode=0o100620)))
        self.assertFalse(root_owned(SimpleNamespace(st_uid=0,st_mode=0o100602)))

    def test_bounded_real_commands_wait_for_clean_exit_and_cap_output(self):
        import sys
        for _ in range(5):
            code,output,truncated=bounded([sys.executable,'-c',"print('ready')"],seconds=2)
            self.assertEqual(code,0);self.assertEqual(output,'ready\n');self.assertFalse(truncated)
        code,output,truncated=bounded([sys.executable,'-c',"print('x'*5000)"],seconds=2,limit=100)
        self.assertTrue(truncated);self.assertEqual(len(output),100)

    def test_uninstantiated_template_and_partial_show_failure_do_not_hide_paqet(self):
        normal=self.command
        def partially_fails(argv,**kwargs):
            code,output,truncated=normal(argv,**kwargs)
            if argv[1]=='list-unit-files':output+='getty@.service enabled\n'
            if argv[1]=='show':
                self.assertNotIn('getty@.service',argv);code=1
            return code,output,truncated
        with patch('donino_link.discovery.bounded',side_effect=partially_fails):
            row=self.selected();self.assertEqual(row['engine'],'paqet')
            self.assertIn('Some systemd',self.inventory.public()['error'])

    def test_scan_reads_yaml_and_only_runs_read_operations(self):
        row=self.selected()
        self.assertEqual(row['engine'],'paqet');self.assertTrue(row['active']);self.assertFalse(row['management_enabled'])
        self.assertNotIn('private-password',json.dumps(row));self.assertNotIn('private-fixture-key',json.dumps(row))
        self.assertTrue(row['editable']);self.assertEqual(row['config']['transport']['kcp']['key'],'[redacted]')
        self.assertTrue(all(cmd[1] in ('list-unit-files','list-units','show') for cmd in self.commands))
        self.assertTrue(self.file.read_text().startswith('# vendor'))

    def test_management_opt_in_does_not_change_or_restart_service(self):
        row=self.selected();before=self.file.read_bytes();self.commands=[]
        result=self.inventory.enable(row['id'],True)
        self.assertFalse(result['changed_service']);self.assertEqual(before,self.file.read_bytes())
        self.assertTrue(all(cmd[1] in ('list-unit-files','list-units','show') for cmd in self.commands))
        self.inventory.control(row['id'],'restart');self.assertIn(['systemctl','restart',self.unit],self.commands)
        self.inventory.enable(row['id'],False)
        with self.assertRaisesRegex(ValueError,'enable management'):self.inventory.control(row['id'],'stop')

    def test_unknown_service_command_path_and_cursor_injection_rejected(self):
        row=self.selected()
        for value in ['ssh.service','../../etc/passwd','a'*24]:
            with self.assertRaises(ValueError):self.inventory.control(value,'stop')
        with self.assertRaises(ValueError):self.inventory.logs(row['id'],'--output=cat\n-u ssh')
        with self.assertRaises(ValueError):self.inventory.enable(row['id'],'true')

    def test_live_journal_redacts_and_returns_incremental_cursor(self):
        row=self.selected();result=self.inventory.logs(row['id'])
        self.assertEqual(result['cursor'],'s=123;i=12;b=123');self.assertNotIn('private-',json.dumps(result))
        self.inventory.logs(row['id'],result['cursor']);self.assertIn('--after-cursor=s=123;i=12;b=123',self.commands[-1])

    def test_local_edit_keeps_secrets_permission_and_original_backup(self):
        row=self.selected();self.inventory.enable(row['id'],True);old=self.file.read_bytes()
        cfg=row['config'];cfg['log']['level']='info';cfg['socks5'].reverse()
        result=self.inventory.edit(row['id'],row['revision'],cfg)
        self.assertTrue(result['restarted']);self.assertTrue(result['backup_saved'])
        new,_=read_config(self.file);self.assertEqual(new['log']['level'],'info')
        self.assertEqual(new['socks5'][0]['password'],'private-password-b');self.assertEqual(new['socks5'][1]['password'],'private-password-a')
        self.assertEqual(new['transport']['kcp']['key'],'private-fixture-key-123456789')
        self.assertEqual(self.file.stat().st_mode&0o777,0o600)
        self.assertEqual(next((self.root/'import-backups'/row['id']).glob('*.original')).read_bytes(),old)

    def test_edit_response_allows_second_save_and_still_rejects_concurrent_change(self):
        row=self.selected();self.inventory.enable(row['id'],True)
        cfg=row['config'];cfg['log']['level']='info'
        first=self.inventory.edit(row['id'],row['revision'],cfg)
        self.assertEqual(first['revision'],hashlib.sha256(self.file.read_bytes()).hexdigest())
        self.assertNotEqual(first['revision'],row['revision'])
        self.assertNotIn('private-',json.dumps(first))
        self.assertEqual(first['config']['log']['level'],'info')
        first['config']['log']['level']='warn'
        second=self.inventory.edit(row['id'],first['revision'],first['config'])
        self.assertEqual(second['revision'],hashlib.sha256(self.file.read_bytes()).hexdigest())
        self.assertEqual(read_config(self.file)[0]['socks5'][0]['password'],'private-password-a')
        self.file.write_bytes(self.file.read_bytes()+b'\n# operator edit\n')
        with self.assertRaisesRegex(ValueError,'changed'):
            self.inventory.edit(row['id'],second['revision'],second['config'])

    def test_restart_failure_restores_exact_original_file(self):
        row=self.selected();self.inventory.enable(row['id'],True);before=self.file.read_bytes()
        cfg=row['config'];cfg['log']['level']='info';self.fail_restart=True
        with self.assertRaises(ValueError):self.inventory.edit(row['id'],row['revision'],cfg)
        self.assertEqual(self.file.read_bytes(),before);self.assertFalse((self.root/'import-edit.json').exists())

    def test_revision_conflict_and_peer_contract_need_explicit_ack(self):
        row=self.selected();self.inventory.enable(row['id'],True)
        cfg=row['config'];cfg['transport']['kcp']['mtu']=1200
        with self.assertRaisesRegex(ValueError,'peer parameters'):self.inventory.edit(row['id'],row['revision'],cfg)
        self.file.write_text(self.file.read_text()+'\n# concurrent root edit\n')
        with self.assertRaisesRegex(ValueError,'changed'):self.inventory.edit(row['id'],row['revision'],cfg,True)

    def test_binary_or_configuration_permissions_prevent_adoption(self):
        row=self.selected();self.file.chmod(0o666)
        with self.assertRaisesRegex(ValueError,'root-owned'):self.inventory.enable(row['id'],True)

    def test_descriptor_change_invalidates_management_grant(self):
        row=self.selected();self.inventory.enable(row['id'],True)
        self.binary=self.root/'paqet';self.binary.write_bytes(b'different executable');self.binary.chmod(0o755)
        with self.assertRaisesRegex(ValueError,'enable management'):self.inventory.control(row['id'],'restart')

    def test_yaml_alias_custom_tag_depth_and_huge_file_rejected(self):
        for text in ['a: &a [x]\nb: *a\n','!!python/object/apply:os.system ["touch /tmp/evil"]','a: '+('['*25)+'1'+(']'*25), 'a: '+('x'*262144)]:
            self.file.write_text(text)
            with self.assertRaises(ValueError):read_config(self.file)

    def test_failed_rollback_retains_recovery_marker_and_later_operator_edit_is_preserved(self):
        row=self.selected();self.inventory.enable(row['id'],True);before=self.file.read_bytes()
        cfg=row['config'];cfg['log']['level']='info'
        normal=self.command
        def fail(argv,**kwargs):
            if argv[:2]==['systemctl','restart']:return 1,'failed',False
            return normal(argv,**kwargs)
        with patch('donino_link.discovery.bounded',side_effect=fail):
            with self.assertRaisesRegex(ValueError,'recovery marker retained'):self.inventory.edit(row['id'],row['revision'],cfg)
        self.assertEqual(self.file.read_bytes(),before);self.assertTrue((self.root/'import-edit.json').exists())
        self.file.write_bytes(before+b'\n# operator changed later\n');later=self.file.read_bytes()
        self.inventory.recover();self.assertEqual(self.file.read_bytes(),later)
        self.assertIn('conflicts',self.inventory.public()['error'])
        self.file.write_bytes(before)
        marker=json.loads((self.root/'import-edit.json').read_text());backup=Path(marker['backup']);backup.write_bytes(b'corrupt')
        self.inventory.recover();self.assertIn('checksum',self.inventory.public()['error']);self.assertEqual(self.file.read_bytes(),before)
        backup.write_bytes(before);self.inventory.recover();self.assertFalse((self.root/'import-edit.json').exists())

    def test_health_expires_and_wildcard_native_listeners_validate(self):
        row=self.selected();self.inventory.health[row['id']]={'time':0,'tcp_ok':True,'udp_ok':True}
        self.assertIsNone(self.inventory.public()['services'][0]['health'])
        import time
        self.inventory.health[row['id']]={'time':time.time(),'revision':row['revision'],'tcp_ok':True,'udp_ok':True}
        self.assertTrue(self.inventory.public()['services'][0]['health']['tcp_ok'])
        self.file.write_bytes(self.file.read_bytes()+b'\n# changed\n');self.inventory.scan(True)
        self.assertIsNone(self.inventory.public()['services'][0]['health'])
        cfg=configuration();cfg['socks5'][0]['listen']=':1080';cfg['forward'][0]['listen']=':8000';validate_paqet(cfg)

    def test_standalone_process_never_gets_a_grant_from_missing_registry(self):
        row=self.selected();private=self.inventory.rows[row['id']]
        private.update(source='process',descriptor=None,editable=False)
        self.assertFalse(self.inventory.public()['services'][0]['management_enabled'])
        self.inventory.scan=lambda force=False:self.inventory.public()
        with self.assertRaisesRegex(ValueError,'enable management'):self.inventory.control(row['id'],'stop')
        with self.assertRaisesRegex(ValueError,'standalone'):self.inventory.enable(row['id'],True)

    def test_validation_accepts_native_defaults_and_rejects_wrong_fields(self):
        cfg=configuration();validate_paqet(cfg)
        for patch_value in [{'mode':'bad'},{'block':'bad'},{'mtu':2000},{'dshard':10},{'wdelay':'yes'}]:
            bad=copy.deepcopy(cfg);bad['transport']['kcp'].update(patch_value)
            with self.assertRaises(ValueError):validate_paqet(bad)
        self.assertEqual(config_arg(['paqet','run','--config=client.yaml'],'/etc/paqet'),'/etc/paqet/client.yaml')
        self.assertEqual(known_engine(['/bin/frpc','-c','x'],'custom.service'),'frp')
        self.assertIsNone(known_engine(['/bin/bash','-c','echo paqet'],'paqet.service'))

if __name__=='__main__':unittest.main()
