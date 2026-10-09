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
            # Install exactly the terminal entry point users run on EACH host.
            password_file=work/'fixture-password';password_file.write_text(PASSWORD+'\n');password_file.chmod(0o600)
            for node in ['foreign','iran']:
                options=['--allow-private-peers'] if node=='iran' else []
                execute(node,'bash','/source/scripts/setup.sh','--role',node,'--address',ips[node],'--password-file','/work/fixture-password',*options)
            # An unrelated operator SSH key must survive pairing and revocation.
            execute('foreign','ssh-keygen','-q','-t','ed25519','-N','','-f','/tmp/operator-key')
            operator_key=execute('foreign','cat','/tmp/operator-key.pub')
            execute('foreign','python3','-c',"import pathlib,sys;p=pathlib.Path('/root/.ssh');p.mkdir(mode=0o700,exist_ok=True);f=p/'authorized_keys';f.write_text(sys.argv[1]);f.chmod(0o600)",operator_key)
            base='http://'+ips['iran']+':8090';foreign_base='http://'+ips['foreign']+':8091'
            def client(base_url):
                jar=http.cookiejar.CookieJar();opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(jar));csrf=''
                def api(path,body=None):
                    req=urllib.request.Request(base_url+path,data=json.dumps(body).encode() if body is not None else None,headers={'Content-Type':'application/json','X-CSRF-Token':csrf})
                    with opener.open(req,timeout=100) as response:return json.load(response)
                def login():
                    nonlocal csrf
                    csrf=api('/api/login',{'password':PASSWORD})['csrf']
                return api,login
            api,login=client(base);foreign_api,foreign_login=client(foreign_base)
            for _ in range(45):
                try:
                    login();foreign_login();state=api('/api/provision/state');assert state['available']
                    assert foreign_api('/api/foreign/state')['available'];break
                except (OSError,AssertionError):time.sleep(1)
            else:raise RuntimeError('standalone role panels unavailable')
            assert api('/api/status')['bootstrap'] and not api('/api/status')['paths']
            assert foreign_api('/api/status')['role']=='foreign'
            code=foreign_api('/api/foreign/code',{})
            p=api('/api/provision/pair',{'name':'Disposable foreign','host':ips['foreign'],'agent_port':9444,'code':code['code']})
            assert execute('foreign','cat','/root/.ssh/authorized_keys')==operator_key
            assert 'restrict ssh-ed25519' in execute('foreign','cat','/var/lib/donino-foreign/authorized_keys')
            assert 'agent_token' not in json.dumps(api('/api/provision/state'))
            try:api('/api/provision/pair',{'name':'Replay','host':ips['foreign'],'agent_port':9444,'code':code['code']})
            except urllib.error.HTTPError as e:assert e.code==400
            else:raise AssertionError('pairing code replay succeeded')
            report['standalone_panels_and_automatic_ssh_pairing']=True
            report['unrelated_operator_ssh_key_preserved']=True
            spec={'profile_id':p['id'],'iran':ips['iran'],'foreign':ips['foreign'],'services':[{'id':'app','listen':'0.0.0.0:18080','target':'127.0.0.1:18081'}],'transports':['frp-wss','frp-quic','backpack-wss','backhaul-wss','browser-wss','paqet'],'experimental':True,'open_ufw':True}
            preview=api('/api/provision/preview',spec)
            job=api('/api/provision/start',{'plan_id':preview['id'],'confirm_replace':True})
            original_job=job['id'];lost_panel=False
            for _ in range(20):
                lease=foreign_api('/api/foreign/state')['lease']
                if lease:break
                time.sleep(.3)
            assert lease and lease['job_id']==original_job
            try:foreign_api('/api/foreign/action',{'unit':'all','action':'test'})
            except urllib.error.HTTPError as e:assert e.code==400
            else:raise AssertionError('foreign action raced with two-node installation')
            report['installation_lease_blocks_competing_actions']=True
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
            # The gateway deliberately needs two successful probe rounds before
            # accepting connections; a single installer probe isn't that state.
            for _ in range(30):
                status=api('/api/status')
                if len(status['paths'])==6 and all(p['healthy'] for p in status['paths']):break
                time.sleep(2)
            else:raise AssertionError('gateway did not reach all-path readiness: '+json.dumps(status))
            payloads=[]
            for carrier in spec['transports']:
                api('/api/action',{'action':'prefer','path':carrier})
                initial=api('/api/status');assert initial['selected']==carrier
                counters=next(p for p in initial['paths'] if p['id']==carrier)
                data=os.urandom(2*1024*1024)
                with socket.create_connection((ips['iran'],18080),timeout=10) as conn:
                    conn.settimeout(60);conn.sendall(data);conn.shutdown(socket.SHUT_WR);result=bytearray()
                    while chunk:=conn.recv(32768):result.extend(chunk)
                assert hashlib.sha256(result).digest()==hashlib.sha256(data).digest(),carrier
                current=next(p for p in api('/api/status')['paths'] if p['id']==carrier)
                assert current['bytes_up']-counters['bytes_up']==len(data) and current['bytes_down']-counters['bytes_down']==len(data),carrier
                payloads.append({'carrier':carrier,'payload_bytes_each_direction':len(data),'sha256_match':True,'half_close':True})
            report['results'].append({'installation':'six-carrier complete','payloads':payloads,'all_path_and_origin_probes':True,'authentication_preserved':True})
            foreign_login()
            for _ in range(30):
                foreign_status=foreign_api('/api/status')
                if foreign_status['telemetry_fresh'] and len(foreign_status['paths'])==6 and all(path['healthy'] for path in foreign_status['paths']) and foreign_status['metrics']:break
                time.sleep(2)
            else:raise AssertionError('foreign panel did not observe real signed probes and metrics: '+json.dumps(foreign_status))
            assert foreign_status['metrics']['bytes_up']>=6*len(data) and foreign_status['metrics']['bytes_down']>=6*len(data)
            report['foreign_signed_health_and_local_traffic_counters']=True
            # Native browser against BOTH actual role panels, without API mocks.
            env={**os.environ,'DONINO_IRAN_URL':base,'DONINO_FOREIGN_URL':foreign_base}
            ui=subprocess.run(['node',str(BASE/'scripts/test-foreign-ui.cjs')],capture_output=True,text=True,env=env,timeout=180)
            if ui.returncode:raise AssertionError('real role UI failed: '+ui.stdout[-3000:]+ui.stderr[-3000:])
            print(ui.stdout)
            report['real_role_ui']=True
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
            foreign_login();foreign_state=foreign_api('/api/foreign/state')
            peer=next(p for p in foreign_state['paired'] if not p['revoked'])
            revoked=foreign_api('/api/foreign/revoke',{'id':peer['id']});assert revoked['revoked']
            assert execute('foreign','cat','/root/.ssh/authorized_keys')==operator_key
            assert peer['id'] not in execute('foreign','cat','/var/lib/donino-foreign/authorized_keys')
            report['pairing_revocation_removes_only_owned_ssh_key']=True
            print(json.dumps(report,ensure_ascii=False))
        finally:
            Path('provision-results.json').write_text(json.dumps(report,indent=2))
            print('FIXTURE REPORT: '+json.dumps(report,ensure_ascii=False))
            for node in ['iran','foreign']:
                try:
                    logs=execute(node,'journalctl','--no-pager','-n','250','-u','donino-control','-u','donino-foreign-agent','-u','donino-link','-u','donino-link-browser-wss')
                    Path('provision-'+node+'.log').write_text(logs)
                    print('SYSTEMD '+node+' JOURNAL:\n'+logs[-10000:])
                    # Private worker logs are deliberately not uploaded: they may
                    # include configuration diagnostics from third-party engines.
                except Exception:pass
                subprocess.run(['docker','rm','-f',PREFIX+'-'+node],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            subprocess.run(['docker','image','rm',PREFIX],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

if __name__=='__main__':main()
