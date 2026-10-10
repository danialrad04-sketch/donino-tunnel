"""Disposable systemd nodes: actual HTTP panel -> Unix worker -> SSH installation.

Run on an isolated Linux CI runner with Docker, never on the user's VPS.
"""
import hashlib
from concurrent.futures import ThreadPoolExecutor
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
            try:
                run('docker','build','-t',PREFIX,str(BASE/'tests/systemd'))
                report['ci_base_image_source']='docker.io/library/debian:12'
            except RuntimeError as error:
                detail=str(error)
                hub_unavailable='429 Too Many Requests' in detail or ('https://auth.docker.io/token' in detail and '504 Gateway Timeout' in detail)
                if not hub_unavailable:raise
                # Google's documented cache of public Docker Hub images. Only
                # the disposable CI base changes; production setup uses apt.
                # https://cloud.google.com/artifact-registry/docs/pull-cached-dockerhub-images
                run('docker','build','--build-arg','BASE_IMAGE=mirror.gcr.io/library/debian:12','-t',PREFIX,str(BASE/'tests/systemd'))
                report['ci_base_image_source']='mirror.gcr.io/library/debian:12 (Docker Hub rate-limit/auth-timeout fallback)'
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
                entry='/source/install-donino.sh' if node=='foreign' else '/source/scripts/setup.sh'
                execute(node,'bash',entry,'--role',node,'--address',ips[node],'--password-file','/work/fixture-password',*options)
            report['standalone_single_file_and_repository_entrypoints']=True
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
            try:p=api('/api/provision/pair',{'name':'Disposable foreign','host':ips['foreign'],'agent_port':9444,'code':code['code']})
            except urllib.error.HTTPError as error:
                reason=json.loads(error.read()).get('error','unknown pairing failure')
                raise AssertionError('fixture pairing failed: '+reason) from error
            assert execute('foreign','cat','/root/.ssh/authorized_keys')==operator_key
            assert 'restrict ssh-ed25519' in execute('foreign','cat','/var/lib/donino-foreign/authorized_keys')
            assert 'agent_token' not in json.dumps(api('/api/provision/state'))
            try:api('/api/provision/pair',{'name':'Replay','host':ips['foreign'],'agent_port':9444,'code':code['code']})
            except urllib.error.HTTPError as e:assert e.code==400
            else:raise AssertionError('pairing code replay succeeded')
            report['standalone_panels_and_automatic_ssh_pairing']=True
            report['unrelated_operator_ssh_key_preserved']=True
            import runpy
            verify=runpy.run_path(str(BASE/'scripts/test-existing-paqet.py'))['verify']
            report['external_paqet_adoption']=verify(api,foreign_api,execute,ips,p,login,foreign_login,base,foreign_base)
            spec={'profile_id':p['id'],'iran':ips['iran'],'foreign':ips['foreign'],'services':[{'id':'app','listen':'0.0.0.0:18080','target':'127.0.0.1:18081'}],'transports':['frp-wss','frp-quic','backpack-wss','backhaul-wss','browser-wss','paqet','donino-mux','donino-continuum'],'experimental':True,'open_ufw':True}
            spec['paqet_options']={'conn':2,'kcp':{'mode':'normal','dshard':10,'pshard':3,'sndwnd':128,'rcvwnd':128},
                                   'pcap_sockbuf':4194304,'local_flag':['PA'],'remote_flag':['PA'],
                                   'forwards':[{'listen':'0.0.0.0:444','target':'127.0.0.1:18082','protocol':'udp'},
                                               {'listen':'127.0.0.1:444','target':'127.0.0.1:18083','protocol':'tcp'}],
                                   'socks5':[{'listen':'127.0.0.1:1080','username':'fixture','password':'fixture-socks-password'}]}
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
            assert len(job['probes'])==len(spec['transports']) and all(p['ok'] for p in job['probes'])
            for node in ['iran','foreign']:
                added=execute(node,'ufw','show','added');assert 'Donino-control-'+job['id'] in added;assert 'fixture-existing' in added
            report['owned_ufw_ports']=True
            login()
            # The gateway deliberately needs two successful probe rounds before
            # accepting connections; a single installer probe isn't that state.
            for _ in range(30):
                status=api('/api/status')
                if len(status['paths'])==len(spec['transports']) and all(p['healthy'] for p in status['paths']):break
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
            report['results'].append({'installation':'eight-carrier complete','payloads':payloads,'all_path_and_origin_probes':True,'authentication_preserved':True})
            report['paqet_native']=json.loads(execute('iran','python3','/source/tests/systemd/paqet_client.py'))
            assert api('/api/provision/paqet-action',{'action':'udp-test'})['ok']
            version=api('/api/provision/paqet-action',{'action':'version'});assert version['ok'] and 'alpha.21' in version['output']
            assert api('/api/provision/paqet-action',{'action':'logs'})['ok']
            for role in ['iran','foreign']:
                cfg=json.loads(execute(role,'cat','/etc/donino-link/current/transports/paqet.yaml'))
                assert cfg['network']['tcp']['local_flag']==['PA'] and cfg['network']['pcap']['sockbuf']==4194304
                assert cfg['transport']['kcp']['dshard']==10 and cfg['transport']['kcp']['pshard']==3
            foreign_login()  # Installation restarted the foreign panel and invalidated its old session.
            for action in ['version','dump']:
                record=foreign_api('/api/foreign/action',{'unit':'donino-link-paqet.service','action':action})
                for _ in range(30):
                    current=next(r for r in foreign_api('/api/foreign/state')['actions'] if r['id']==record['id'])
                    if current['status']!='running':break
                    time.sleep(.5)
                assert current['status']=='succeeded' and current['result']['ok'],current
            for _ in range(30):
                remote=foreign_api('/api/status');paqet_path=next(p for p in remote['paths'] if p['id']=='paqet')
                if paqet_path.get('udp_ok') is True:break
                time.sleep(1)
            assert paqet_path.get('udp_ok') is True,paqet_path
            safe=api('/api/provision/state');assert 'fixture-socks-password' not in json.dumps(safe)
            assert safe['active_spec']['paqet_options']['socks5'][0]['authenticated']
            report['paqet_management']={'fixed_command_diagnostics':True,'bounded_foreign_capture':True,
                                       'signed_udp_health_on_both_panels':True,'advanced_config_preserved':True,'credentials_not_exposed':True}
            api('/api/action',{'action':'prefer','path':'donino-mux'})
            initial_mux=next(p for p in api('/api/status')['paths'] if p['id']=='donino-mux')
            def mux_payload(_):
                block=os.urandom(1024*1024)
                with socket.create_connection((ips['iran'],18080),timeout=10) as conn:
                    conn.settimeout(60);conn.sendall(block);conn.shutdown(socket.SHUT_WR);received=bytearray()
                    while chunk:=conn.recv(32768):received.extend(chunk)
                assert hashlib.sha256(received).digest()==hashlib.sha256(block).digest()
                return len(block)
            with ThreadPoolExecutor(max_workers=8) as pool:mux_sizes=list(pool.map(mux_payload,range(8)))
            final_mux=next(p for p in api('/api/status')['paths'] if p['id']=='donino-mux')
            for key in ['bytes_up','bytes_down']:assert final_mux[key]-initial_mux[key]==sum(mux_sizes)
            report['mux_concurrent_payloads']={'flows':8,'bytes_each_direction_per_flow':1024*1024,'sha256_match':True,'half_close':True,'real_counters_match':True}
            # Keep one application's TCP socket open while forcibly killing
            # carrier sockets in the foreign kernel. Origin is an EOF responder.
            api('/api/action',{'action':'prefer','path':'donino-continuum'})
            chunks=[os.urandom(256*1024) for _ in range(4)]
            with socket.create_connection((ips['iran'],18080),timeout=10) as conn:
                conn.settimeout(60)
                for index,block in enumerate(chunks):
                    conn.sendall(block)
                    # Wait for this chunk to reach the origin TCP writer.
                    for _ in range(100):
                        stats=json.loads(execute('foreign','cat','/var/lib/donino-link/continuum-foreign.json'))
                        if stats['bytes_up']>=len(data)+(index+1)*len(block):break
                        time.sleep(.1)
                    else:raise AssertionError('Continuum upload stopped progressing')
                    if index<3:
                        previous=stats['protocol']['recoveries']
                        killed=execute('foreign','ss','-K','state','established','sport','=',':24450')
                        assert ':24450' in killed,'no Continuum TLS socket was killed'
                        for _ in range(100):
                            stats=json.loads(execute('foreign','cat','/var/lib/donino-link/continuum-foreign.json'))
                            if stats['protocol']['recoveries']>previous:break
                            time.sleep(.1)
                        else:raise AssertionError('Continuum session did not resume')
                conn.shutdown(socket.SHUT_WR);received=bytearray()
                while block:=conn.recv(32768):received.extend(block)
            expected=b''.join(chunks)
            assert hashlib.sha256(received).digest()==hashlib.sha256(expected).digest()
            report['continuum_kernel_lane_recovery']={'lane_aborts':3,'bytes_each_direction':len(expected),'same_application_tcp_socket':True,'sha256_match':True,'half_close':True}
            api('/api/action',{'action':'auto'})
            assert api('/api/status')['selected']=='frp-wss'
            # Delay ONLY the first carrier's real outbound packets on the
            # disposable Iran node. Other carriers, SSH and panels are intact.
            execute('iran','tc','qdisc','add','dev','eth0','root','handle','1:','prio')
            execute('iran','tc','qdisc','add','dev','eth0','parent','1:3','handle','30:','netem','delay','150ms')
            execute('iran','tc','filter','add','dev','eth0','protocol','ip','parent','1:','prio','1','u32','match','ip','sport','24443','0xffff','flowid','1:3')
            api('/api/action',{'action':'adaptive'})
            for _ in range(30):
                initial=api('/api/status');delayed=next(p for p in initial['paths'] if p['id']=='frp-wss')
                if delayed['healthy'] and delayed['quality']['probe_ms'] and delayed['quality']['probe_ms']>=100 and initial['selected'] not in (None,'frp-wss'):break
                time.sleep(2)
            else:raise AssertionError('adaptive did not avoid the healthy delayed carrier: '+json.dumps(initial))
            report['adaptive_real_netem']={'delayed_carrier':'frp-wss','added_outbound_delay_ms':150,'delayed_carrier_still_healthy':True,'selected':initial['selected'],'delayed_probe_ms':delayed['quality']['probe_ms']}
            adaptive_data=os.urandom(1024*1024)
            with socket.create_connection((ips['iran'],18080),timeout=10) as conn:
                conn.settimeout(60);conn.sendall(adaptive_data);conn.shutdown(socket.SHUT_WR);result=bytearray()
                while chunk:=conn.recv(32768):result.extend(chunk)
            assert hashlib.sha256(result).digest()==hashlib.sha256(adaptive_data).digest()
            after_adaptive=api('/api/status')
            for key in ['bytes_up','bytes_down']:
                assert sum(p[key] for p in after_adaptive['paths'])-sum(p[key] for p in initial['paths'])==len(adaptive_data)
            report['adaptive_actual_payload']={'payload_bytes_each_direction':len(adaptive_data),'sha256_match':True,'half_close':True,'real_counters_match':True}
            execute('iran','tc','qdisc','del','dev','eth0','root')
            api('/api/action',{'action':'static'})
            foreign_login()
            for _ in range(30):
                foreign_status=foreign_api('/api/status')
                counters=foreign_status.get('metrics')
                # Relays publish once/second and the monitor samples every five
                # seconds. Require the payload's completed counters, not merely
                # an earlier (valid but smaller) process snapshot.
                if foreign_status['telemetry_fresh'] and len(foreign_status['paths'])==len(spec['transports']) and all(path['healthy'] for path in foreign_status['paths']) and counters and counters['bytes_up']>=len(spec['transports'])*len(data) and counters['bytes_down']>=len(spec['transports'])*len(data):break
                time.sleep(2)
            else:raise AssertionError('foreign panel did not observe real signed probes and metrics: '+json.dumps(foreign_status))
            assert foreign_status['metrics']['bytes_up']>=len(spec['transports'])*len(data) and foreign_status['metrics']['bytes_down']>=len(spec['transports'])*len(data)
            report['foreign_signed_health_and_local_traffic_counters']=True
            report['foreign_traffic_counters']={k:foreign_status['metrics'][k] for k in ['bytes_up','bytes_down']}
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
            blocked.pop('paqet_options',None)
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
            for _ in range(30):
                revoked_status=foreign_api('/api/status')
                if not revoked_status['telemetry_fresh']:break
                time.sleep(2)
            assert not revoked_status['telemetry_fresh'] and all(not path['healthy'] for path in revoked_status['paths'])
            for node in ['iran','foreign']:
                shipped=execute(node,'/opt/donino-link/current/venv/bin/python','-c',"from pathlib import Path;import donino_link.panel,hashlib;print(hashlib.sha256((Path(donino_link.panel.__file__).parent/'web/app.js').read_bytes()).hexdigest())").strip()
                assert shipped==hashlib.sha256((BASE/'donino_link/web/app.js').read_bytes()).hexdigest(),node+' shipped a different panel asset'
            unknown_ui=subprocess.run(['node',str(BASE/'scripts/test-foreign-ui.cjs')],capture_output=True,text=True,env={**env,'DONINO_EXPECT_UNKNOWN':'1'},timeout=90)
            if unknown_ui.returncode:raise AssertionError('unknown health UI failed: '+unknown_ui.stderr[-3000:])
            print(unknown_ui.stdout);report['revoked_peer_health_becomes_unknown']=True
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
