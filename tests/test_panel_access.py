import json
import os
import tempfile
import unittest
from pathlib import Path
from donino_link.config import atomic_json,load_config
from donino_link.panel_access import configure_panel
from test_core import configuration

class PanelAccessTests(unittest.TestCase):
    def test_public_http_explicit_and_credentials_preserved(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);path=root/'node.json';config=configuration(root)
            atomic_json(path,config);path.chmod(0o640)
            old=path.stat()
            result=configure_panel(path,'0.0.0.0:18090',http=True,public_host='panel.example.com')
            current=load_config(path)
            self.assertEqual(current['panel']['listen'],'0.0.0.0:18090')
            self.assertTrue(current['panel']['allow_insecure_http'])
            self.assertEqual(current['health_key'],config['health_key'])
            self.assertEqual(current['panel']['credentials_file'],config['panel']['credentials_file'])
            self.assertEqual(path.stat().st_mode&0o777,0o640)
            self.assertEqual((path.stat().st_uid,path.stat().st_gid),(old.st_uid,old.st_gid))
            self.assertEqual(result['url'],'http://panel.example.com:18090')
            self.assertEqual(json.loads(Path(result['backup']).read_text())['panel']['listen'],config['panel']['listen'])

    def test_implicit_public_http_and_port_collision_do_not_mutate(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);path=root/'node.json';atomic_json(path,configuration(root));old=path.read_bytes()
            for listen,http in [('0.0.0.0:18090',False),('0.0.0.0:12345',True)]:
                with self.assertRaises(ValueError):configure_panel(path,listen,http=http)
                self.assertEqual(path.read_bytes(),old)

    def test_allow_http_must_be_boolean(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);path=root/'node.json';config=configuration(root)
            config['panel'].update(listen='0.0.0.0:18090',allow_insecure_http='true');atomic_json(path,config)
            with self.assertRaises(ValueError):load_config(path)

    def test_incomplete_tls_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);path=root/'node.json';config=configuration(root)
            config['panel']['tls_cert']='fake.crt';atomic_json(path,config)
            with self.assertRaises(ValueError):load_config(path)
