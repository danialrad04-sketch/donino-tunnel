"""Create an independently installed service ONLY inside disposable CI nodes."""
import json
import sys
from pathlib import Path
import yaml
from donino_link.artifacts import install_engines
from donino_link.network import discover

role,peer=sys.argv[1:]
assert role in ('iran','foreign') and Path('/source/tests/systemd/Dockerfile').is_file()
install_engines(['paqet'],'/root/vendor-paqet/bin')
interface,local_ip,mac=discover(peer)
cfg={'role':'client' if role=='iran' else 'server','log':{'level':'info'},
     'network':{'interface':interface,'ipv4':{'addr':local_ip+(':0' if role=='iran' else ':33535'),'router_mac':mac}},
     'transport':{'protocol':'kcp','conn':2,'kcp':{'mode':'normal','block':'aes-128-gcm','key':'external-fixture-key-123456789012345'}}}
if role=='iran':
    cfg.update(server={'addr':peer+':33535'},socks5=[{'listen':'127.0.0.1:1089','username':'fixture-existing','password':'external-socks-password'}],
               forward=[{'listen':'127.0.0.1:18984','target':'127.0.0.1:18082','protocol':'udp'},
                        {'listen':'127.0.0.1:18986','target':'127.0.0.1:18083','protocol':'tcp'}])
else:cfg['listen']={'addr':':33535'}
folder=Path('/root/vendor-paqet/config');folder.mkdir(mode=0o700,exist_ok=True)
file=folder/(role+'.yaml');file.write_text('# Independent installation; preserve this original YAML.\n'+yaml.safe_dump(cfg));file.chmod(0o600)
unit='vendor-edge.service' if role=='iran' else 'vendor-exit.service'
Path('/etc/systemd/system/'+unit).write_text('[Unit]\nDescription=Independent fixture Paqet\nAfter=network.target\n[Service]\nExecStart=/root/vendor-paqet/bin/paqet run -c '+str(file)+'\nRestart=no\n[Install]\nWantedBy=multi-user.target\n')
print(json.dumps({'unit':unit,'file':str(file)}))
