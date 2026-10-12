"""Exercise shipped dependencies with outbound Python socket connections blocked."""
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HELPER = ROOT / 'donino_link/resources/python-runtime.sh'
WHEELS = ROOT / 'donino_link/resources/wheelhouse'


class OfflineRuntimeTests(unittest.TestCase):
    def test_wheels_are_verified_portable_and_include_licenses(self):
        entries = dict(line.split('  ', 1)[::-1] for line in (WHEELS / 'SHA256SUMS').read_text().splitlines())
        self.assertEqual(set(entries), {p.name for p in WHEELS.glob('*.whl')})
        for name, digest in entries.items():
            with self.subTest(wheel=name):
                self.assertTrue(name.endswith('-none-any.whl'))
                self.assertEqual(hashlib.sha256((WHEELS / name).read_bytes()).hexdigest(), digest)
                with zipfile.ZipFile(WHEELS / name) as wheel:
                    self.assertFalse(any(n.endswith(('.so', '.pyd')) for n in wheel.namelist()))
                    self.assertTrue(any('license' in n.lower() or 'copying' in n.lower() for n in wheel.namelist()))

    def test_install_without_pypi_and_ship_dependencies_to_next_node(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stage = root / 'stage'
            stage.mkdir()
            shutil.copytree(ROOT / 'donino_link', stage / 'donino_link', ignore=shutil.ignore_patterns('__pycache__'))
            shutil.copy2(ROOT / 'pyproject.toml', stage / 'pyproject.toml')
            guard = root / 'guard'
            guard.mkdir()
            marker = root / 'network-attempt'
            (guard / 'sitecustomize.py').write_text('''import socket, os
def deny(*args, **kwargs):
    with open(os.environ['DONINO_NETWORK_MARKER'], 'a') as file: file.write('attempt\\n')
    raise RuntimeError('network disabled for offline installation test')
socket.socket.connect = deny
socket.socket.connect_ex = deny
socket.create_connection = deny
''')
            env = {**os.environ, 'PYTHONPATH': str(guard), 'DONINO_NETWORK_MARKER': str(marker),
                   'PIP_INDEX_URL': 'https://unreachable.invalid/simple', 'PIP_EXTRA_INDEX_URL': 'https://unreachable.invalid/simple'}
            result = subprocess.run(['bash', '-c', 'set -Eeuo pipefail; source "$1"; donino_python_runtime "$2" "$3"',
                                     'offline-test', str(HELPER), str(stage), sys.executable], env=env,
                                    capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(marker.exists(), 'installer attempted an outbound Python connection')
            python = stage / 'venv/bin/python'
            node = root / 'node'
            node.mkdir()
            code = '''import aiohttp, yaml, sys
from pathlib import Path
from donino_link.deploy import build_payload
assert aiohttp.__version__ == '3.14.4'
assert yaml.__version__ == '6.0.3'
build_payload(sys.argv[1], sys.argv[2])
p = Path(sys.argv[2]) / 'donino_link/resources/wheelhouse'
assert (p / 'SHA256SUMS').is_file()
assert len(list(p.glob('*.whl'))) == 15
'''
            probe = subprocess.run([str(python), '-c', code, str(node), str(root / 'next-node')], cwd=root,
                                   env=env, capture_output=True, text=True, timeout=20)
            self.assertEqual(probe.returncode, 0, probe.stdout + probe.stderr)
            cli = subprocess.run([str(stage / 'venv/bin/donino-link'), '--help'], cwd=root, env=env,
                                 capture_output=True, text=True, timeout=20)
            self.assertEqual(cli.returncode, 0, cli.stderr)

    def test_corrupt_wheel_fails_before_creating_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            wheels = root / 'donino_link/resources/wheelhouse'
            wheels.mkdir(parents=True)
            (wheels / 'bad.whl').write_bytes(b'corrupt')
            (wheels / 'SHA256SUMS').write_text('0' * 64 + '  bad.whl\n')
            result = subprocess.run(['bash', '-c', 'source "$1"; donino_python_runtime "$2"',
                                     'corrupt-test', str(HELPER), str(root)], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / 'venv').exists())
