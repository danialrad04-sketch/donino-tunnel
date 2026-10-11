"""Read-only staged-node checks. Fails before stopping the active installation."""
import argparse
import json
import os
import re
import shutil
import signal
import socket
import subprocess
from pathlib import Path
from .config import endpoint


def conflicts(rows, listeners, managed_pid):
    wanted = {(item['protocol'], item['port']) for item in listeners}
    found = []
    for row in rows.splitlines():
        parts = row.split()
        if len(parts) < 6 or parts[0] not in ('tcp', 'udp'): continue
        try: port = int(parts[4].rsplit(':', 1)[1])
        except ValueError: continue
        if (parts[0], port) not in wanted: continue
        pids = [int(p) for p in re.findall(r'pid=(\d+)', row)]
        if not pids or any(not managed_pid(p) for p in pids): found.append(f'{parts[0]}:{port}')
    return sorted(set(found))


def managed_pid(pid):
    try:
        cgroup = Path(f'/proc/{pid}/cgroup').read_text()
        return bool(re.search(r'/donino-link(?:-[a-z0-9-]+)?\.service(?:/|$)', cgroup, re.M))
    except OSError: return False


def check(node):
    node = Path(node)
    install = json.loads((node/'install.json').read_text())
    if shutil.disk_usage(node).free < 512*1024*1024:
        raise ValueError('at least 512 MiB of free space is required')
    rows = subprocess.check_output(['ss', '-H', '-lntup'], text=True, timeout=10)
    occupied = conflicts(rows, install.get('listeners', []), managed_pid)
    if occupied: raise ValueError('ports owned by other services: '+', '.join(occupied))
    if install['role']=='foreign' and 'panel' in json.loads((node/'node.json').read_text()):
        settings=Path('/etc/donino-foreign-agent.json')
        if settings.exists():
            port=json.loads(settings.read_text())['port']
            def agent_pid(pid):
                try:return '/donino-foreign-agent.service' in Path(f'/proc/{pid}/cgroup').read_text()
                except OSError:return False
            if conflicts(rows,[{'protocol':'tcp','port':port}],agent_pid):raise ValueError('foreign pairing port is owned by another service')
    if install.get('browser'):
        total = int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemTotal:')))*1024
        if total < 1500*1024*1024: raise ValueError('BrowserLink requires at least 1.5 GiB host RAM')
        flag = Path('/proc/sys/kernel/unprivileged_userns_clone')
        if flag.exists() and flag.read_text().strip() != '1': raise ValueError('Chromium sandbox requires enabled unprivileged user namespaces')
        config=json.loads((node/'transports/browser-wss.json').read_text())
        browser=config.get('chromium','/usr/bin/chromium')
        # Test the actual renderer using the same IPC/flags as BrowserLink.
        # The probe opens only about:blank, without credentials or network URLs.
        bridge=Path(__file__).parent/'resources/browser_bridge.js'
        command=['runuser','-u','donino-link','--','env','DONINO_CHROMIUM='+browser,'node',str(bridge),'--sandbox-check']
        launch=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        try:
            stdout,stderr=launch.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            os.killpg(launch.pid,signal.SIGKILL)
            _,stderr=launch.communicate()
            raise ValueError('Native Chromium sandbox startup timed out before activation: '+stderr.decode(errors='replace')[-1200:])
        if launch.returncode or b'"sandbox_startup":true' not in stdout:
            raise ValueError('Native Chromium sandbox startup failed before activation: '+stderr.decode(errors='replace')[-1200:])
    if install['role'] == 'foreign':
        config = json.loads((node/'node.json').read_text())
        for name, target in config.get('targets', {}).items():
            with socket.create_connection(endpoint(target), timeout=3): pass
    return {'ports': 'available or managed by Donino', 'disk': 'ok', 'origin_services': 'reachable' if install['role']=='foreign' else 'checked on foreign'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--node', required=True)
    try: print(json.dumps(check(parser.parse_args().node)))
    except (ValueError, OSError) as error: parser.exit(1, str(error)+'\n')
