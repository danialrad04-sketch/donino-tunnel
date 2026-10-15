import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from donino_link.vpn_backend import extract, initial_settings, Backend
from donino_link.ecosystem import modern_client


class BackendTests(unittest.TestCase):
    def archive(self, root, entries):
        archive = root/'archive.tar.gz'
        with tarfile.open(archive, 'w:gz') as out:
            for name, payload, link in entries:
                member = tarfile.TarInfo(name)
                if link:
                    member.type = tarfile.SYMTYPE;member.linkname = link
                else:
                    member.size = len(payload)
                out.addfile(member, None if link else io.BytesIO(payload))
        return archive

    def test_vendor_extraction_only_known_regular_files(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            archive = self.archive(root, [('x-ui/x-ui', b'\x7fELFui', None),
                ('x-ui/bin/xray-linux-amd64', b'\x7fELFcore', None),
                ('../../outside', b'bad', None), ('x-ui/x-ui.sh', b'executable vendor shell', None)])
            extract(archive, root/'output', 'amd64')
            self.assertEqual((root/'output/x-ui').stat().st_mode & 0o777, 0o755)
            self.assertFalse((root/'output/x-ui.sh').exists())
            self.assertFalse((root/'outside').exists())
            archive = self.archive(root, [('x-ui/x-ui', b'', '/etc/shadow')])
            with self.assertRaises(ValueError): extract(archive, root/'bad', 'amd64')

    def test_fresh_backend_has_no_public_subscription_listener(self):
        settings = initial_settings()
        self.assertEqual(settings['subEnable'], 'false')
        self.assertEqual(settings['subListen'], '127.0.0.1')
        self.assertEqual(settings['subJsonEnable'], 'false')
        template = json.loads(settings['xrayTemplateConfig'])
        self.assertEqual(template['inbounds'][0]['listen'], '127.0.0.1')
        self.assertEqual(template['inbounds'][0]['port'], 20541)

    def test_numeric_database_id_is_never_sent_as_client_uuid(self):
        record = {'id': 42, 'uuid': 'stable-uuid', 'email': 'alice', 'traffic': {'up': 9},
                  'inboundIds': [1], 'allowedIPs': '10.0.0.1/32, 10.0.0.2/32', 'reverse': {'tag': 'keep'}}
        result = modern_client(record)
        self.assertEqual(result['id'], 'stable-uuid')
        self.assertEqual(result['allowedIPs'], ['10.0.0.1/32', '10.0.0.2/32'])
        self.assertEqual(result['reverse'], record['reverse'])
        self.assertNotIn('traffic', result)
        self.assertEqual(record['id'], 42)

    def test_receipts_are_outside_backend_writable_state(self):
        backend = Backend('/tmp/example/runtime', '/tmp/example/release', '/tmp/example/units')
        self.assertNotEqual(backend.private, backend.root)
        self.assertFalse(backend.private.is_relative_to(backend.root))
        for request in ({}, {'confirm_install': False}, {'confirm_install': True, 'url': 'evil'}):
            with self.assertRaises(ValueError): backend.install(request)
