"""Disposable systemd nodes: actual HTTP panel -> Unix worker -> SSH installation.

Run on an isolated Linux CI runner with Docker, never on the user's VPS.
"""
import hashlib
import http.cookiejar
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from donino_link.config import atomic_json
from donino_link.deploy import build_payload
from donino_link.plan import make_plan

BASE=Path(__file__).resolve().parent.parent
PASSWORD='systemd-fixture-password-123'
PREFIX='donino-ci-'+str(os.getpid())

def run(*args, data=None):
    r=subprocess.run(args,input=data,capture_output=True,timeout=1800)
    if r.returncode:
        raise RuntimeError('CI command failed: '+str(args[:3])+'\n'+r.stdout.decode(errors='replace')[-12000:]+r.stderr.decode(errors='replace')[-12000:])
    return r.stdout.decode()

def execute(node,*args,data=None):return run('docker','exec','-i',PREFIX+'-'+node,*args,data=data)

def main():
    report={'scope':'Two disposable Debian 12 systemd containers, private Docker bridge; not a real Iran WAN','results':[]}
    with tempfile.TemporaryDirectory(prefix='donino-systemd-') as tmp:
        work=Path(tmp)
        try:
            run('docker','build','-t',PREFIX,str(BASE/'tests/systemd'))
            for node in ['iran','foreign']:
                run('docker','run','-d','--name',PREFIX+'-'+node,'--privileged','--cgroupns=host','--tmpfs','/run','--tmpfs','/tmp','-v','/sys/fs/cgroup:/sys/fs/cgroup:rw','-v',str(BASE)+':/source:ro','-v',str(work)+':/work',PREFIX)
                for _ in range(60):
                    try:
                        execute(node,'systemctl','is-active','ssh.service');break
                    except RuntimeError:time.sleep(1)
                else:raise RuntimeError('systemd/SSH did not start in '+node+'\n'+run('docker','logs',PREFIX+'-'+node))
            ips={node:json.loads(run('docker','inspect',PREFIX+'-'+node))[0]['NetworkSettings']['IPAddress'] for node in ['iran','foreign']}
            for node in ['iran','foreign']:
                for port in ([22,8090,24443,18080] if node=='iran' else [22]):execute(node,'ufw','allow',str(port)+'/tcp','comment','fixture-existing')
                execute(node,'ufw','--force','enable')
            execute('foreign','python3','-c',"import subprocess;subprocess.Popen(['python3','/source/tests/systemd/origin.py'],start_new_session=True,stdout=open('/tmp/origin.log','w'),stderr=subprocess.STDOUT)")
            plan=work/'baseline'
            make_plan(plan,ips['iran'],ips['foreign'],[{'id':'app','listen':'0.0.0.0:18080','target':'127.0.0.1:18081'}],['frp-wss'],PASSWORD)
            cfg=json.loads((plan/'iran/node.json').read_text());cfg['panel'].update(listen='0.0.0.0:8090',allow_insecure_http=True);atomic_json(plan/'iran/node.json',cfg)
            execute('iran','python3','-c',"import json;json.dump({'allow_private_peers':True},open('/etc/donino-control.json','w'))")
            for node in ['foreign','iran']:
                build_payload(plan/node,work/('payload-'+node))
                execute(node,'bash','/work/payload-'+node+'/scripts/install-node.sh','/work/payload-'+node)
            for _ in range(30):
                try:
                    public_key=execute('iran','cat','/var/lib/donino-control/identity.pub').strip();break
                except RuntimeError:time.sleep(1)
            else:raise RuntimeError('controller key initialization failed')
            execute('foreign','python3','-c',"import pathlib,sys;p=pathlib.Path('/root/.ssh');p.mkdir(mode=0o700,exist_ok=True);f=p/'authorized_keys';f.write_text(sys.argv[1]+'\\n');f.chmod(0o600)",public_key)
            pin=execute('foreign','ssh-keygen','-lf','/etc/ssh/ssh_host_ed25519_key.pub').split()[1]
            base='http://'+ips['iran']+':8090'
            jar=http.cookiejar.CookieJar();opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(jar));csrf=''
            def api(path,body=None):
                req=urllib.request.Request(base+path,data=json.dumps(body).encode() if body is not None else None,headers={'Content-Type':'application/json','X-CSRF-Token':csrf})
                with opener.open(req,timeout=100) as response:return json.load(response)
            def login():
                nonlocal csrf
                csrf=api('/api/login',{'password':PASSWORD})['csrf']
            for _ in range(30):
                try:login();state=api('/api/provision/state');assert state['available'];break
                except (OSError,AssertionError):time.sleep(1)
            else:raise RuntimeError('panel/controller unavailable')
            p=api('/api/provision/profiles',{'name':'Disposable foreign','host':ips['foreign'],'port':22,'fingerprint':pin})
            spec={'profile_id':p['id'],'iran':ips['iran'],'foreign':ips['foreign'],'services':[{'id':'app','listen':'0.0.0.0:18080','target':'127.0.0.1:18081'}],'transports':['frp-wss','frp-quic','backpack-wss','backhaul-wss','browser-wss','paqet'],'experimental':True,'open_ufw':True}
            preview=api('/api/provision/preview',spec)
            job=api('/api/provision/start',{'plan_id':preview['id'],'confirm_replace':True})
            original_job=job['id'];lost_panel=False
            for _ in range(900):
                try:
                    state=api('/api/provision/state');job=next(j for j in state['jobs'] if j['id']==original_job)
                    if job['status']!='running' and not state['busy']:break
                except urllib.error.HTTPError as e:
                    if e.code==401:login();lost_panel=True
                    else:raise
                except OSError:lost_panel=True
                time.sleep(2)
            else:raise RuntimeError('installation job timed out')
            report['job']=job;report['panel_restarted']=lost_panel
            if job['status']!='succeeded':
                import re
                private=execute('iran','cat','/var/lib/donino-control/jobs/'+job['id']+'/private.log')
                private=re.sub(r'[0-9a-f]{64}','[redacted]',private)
                private=re.sub(r'(?im)^.*(?:token|secret|password|private key).*$','[redacted sensitive line]',private)
                print('FIXTURE INSTALLER DIAGNOSTICS:\n'+private[-16000:])
            assert job['status']=='succeeded',json.dumps(job)
            assert len(job['probes'])==6 and all(p['ok'] for p in job['probes'])
            for node in ['iran','foreign']:
                added=execute(node,'ufw','show','added');assert 'Donino-control-'+job['id'] in added;assert 'fixture-existing' in added
            report['owned_ufw_ports']=True
            login()
            data=os.urandom(2*1024*1024)
            with socket.create_connection((ips['iran'],18080),timeout=10) as conn:
                conn.settimeout(30);conn.sendall(data);conn.shutdown(socket.SHUT_WR);result=bytearray()
                while chunk:=conn.recv(32768):result.extend(chunk)
            assert hashlib.sha256(result).digest()==hashlib.sha256(data).digest()
            report['results'].append({'installation':'six-carrier complete','payload_bytes_each_direction':len(data),'half_close':True,'all_path_and_origin_probes':True,'authentication_preserved':True})
            # Foreign target unavailable must fail in preparation and preserve the
            # successful installation on BOTH nodes, before activation.
            before={node:execute(node,'readlink','-f','/opt/donino-link/current').strip() for node in ['iran','foreign']}
            bad={**spec,'services':[{'id':'app','listen':'0.0.0.0:18080','target':'127.0.0.1:18999'}]}
            p=api('/api/provision/preview',bad);failed=api('/api/provision/start',{'plan_id':p['id'],'confirm_replace':True})
            for _ in range(150):
                state=api('/api/provision/state');row=next(j for j in state['jobs'] if j['id']==failed['id'])
                if row['status']!='running' and not state['busy']:break
                time.sleep(2)
            assert row['status']=='failed',json.dumps(row)
            assert not row['activated']
            after={node:execute(node,'readlink','-f','/opt/donino-link/current').strip() for node in ['iran','foreign']}
            assert before==after
            report['results'].append({'unavailable_origin':'fails before activation','previous_releases_preserved':True})
            blocked={**spec,'transports':['frp-wss'],'carrier_base':24543,'open_ufw':False}
            p=api('/api/provision/preview',blocked);failed=api('/api/provision/start',{'plan_id':p['id'],'confirm_replace':True})
            for _ in range(180):
                try:
                    state=api('/api/provision/state');row=next(j for j in state['jobs'] if j['id']==failed['id'])
                    if row['status']!='running' and not state['busy']:break
                except urllib.error.HTTPError as error:
                    if error.code==401:login()
                    else:raise
                except OSError:pass
                time.sleep(2)
            assert row['status']=='failed' and row['activated']==['foreign','iran'],json.dumps(row)
            after={node:execute(node,'readlink','-f','/opt/donino-link/current').strip() for node in ['iran','foreign']}
            assert before==after
            assert [e['stage'] for e in row['events'] if e['stage'].startswith('rollback') and e['status']=='done']==['rollback-iran','rollback-foreign']
            login();assert api('/api/provision/state')['available']
            report['results'].append({'blocked_carrier':'fails after activation','actual_two_node_rollback':True,'panel_and_password_restored':True})
            print(json.dumps(report,ensure_ascii=False))
        finally:
            Path('provision-results.json').write_text(json.dumps(report,indent=2))
            for node in ['iran','foreign']:
                try:
                    logs=execute(node,'journalctl','--no-pager','-n','250','-u','donino-control','-u','donino-link','-u','donino-link-browser-wss')
                    Path('provision-'+node+'.log').write_text(logs)
                    print('SYSTEMD '+node+' JOURNAL:\n'+logs[-10000:])
                    # Private worker logs are deliberately not uploaded: they may
                    # include configuration diagnostics from third-party engines.
                except Exception:pass
                subprocess.run(['docker','rm','-f',PREFIX+'-'+node],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            subprocess.run(['docker','image','rm',PREFIX],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

if __name__=='__main__':main()
