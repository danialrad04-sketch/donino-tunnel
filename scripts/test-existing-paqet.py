"""Integration before any Donino carrier is activated. CI containers only."""
import hashlib
import json
import os
import subprocess
import time
import urllib.error
from pathlib import Path


def verify(api,foreign_api,execute,ips,profile,login,foreign_login,base,foreign_base):
    units={};files={}
    for node in ('foreign','iran'):
        peer=ips['iran' if node=='foreign' else 'foreign']
        execute(node,'apt-get','install','-y','libpcap0.8')
        meta=json.loads(execute(node,'/opt/donino-link/current/venv/bin/python','/source/tests/systemd/external_paqet.py',node,peer))
        units[node]=meta['unit'];files[node]=meta['file']
        execute(node,'systemctl','daemon-reload')
        if node=='foreign':
            execute(node,'ufw','allow','33535/tcp','comment','fixture-vendor')
            execute(node,'/opt/donino-link/current/venv/bin/python','-m','donino_link.raw_rules','apply','--peer',peer,'--port','33535')
        execute(node,'systemctl','enable','--now',meta['unit'])
    def snapshot(node):
        return {'pid':execute(node,'systemctl','show','--value','--property=MainPID',units[node]).strip(),
                'config':execute(node,'cat',files[node]),'firewall':execute(node,'ufw','show','added')}
    before={n:snapshot(n) for n in units}
    assert all(int(r['pid'])>0 for r in before.values())
    def row(node):
        endpoint='/api/provision/state' if node=='iran' else '/api/foreign/state'
        rows=(api if node=='iran' else foreign_api)(endpoint)['inventory']['services']
        return next((r for r in rows if r['unit']==units[node]),None)
    for _ in range(20):
        detected={n:row(n) for n in units}
        if all(detected.values()):break
        time.sleep(1)
    if not all(detected.values()):
        for node in units:
            call=api if node=='iran' else foreign_api
            url='/api/provision/state' if node=='iran' else '/api/foreign/state'
            print('DETECTION '+node+': '+json.dumps(call(url)['inventory']))
            print(execute(node,'systemctl','show','--property=Id,MainPID,ActiveState,ExecStart',units[node]))
        raise AssertionError('independent Paqet not detected')
    for node,r in detected.items():
        assert r['engine']=='paqet' and r['active'] and r['editable'] and not r['management_enabled'] and not r['managed_by_donino'],r
        public=json.dumps(r);assert 'external-fixture-key-' not in public and 'external-socks-password' not in public
        assert snapshot(node)==before[node],'passive scan mutated vendor installation'
        call=api if node=='iran' else foreign_api;url='/api/provision/imported-action' if node=='iran' else '/api/foreign/imported-action'
        try:call(url,{'id':r['id'],'action':'restart'})
        except urllib.error.HTTPError as e:assert e.code==400
        else:raise AssertionError('unadopted vendor service can be controlled')
        call(url,{'id':r['id'],'action':'manage','enabled':True})
        assert snapshot(node)==before[node],'adoption restarted or rewrote vendor installation'
    url='/api/provision/imported-action';rid=detected['iran']['id']
    for _ in range(12):
        tested=api(url,{'id':rid,'action':'test','profile_id':profile['id']})
        if tested['tcp_ok'] and tested['udp_ok']:break
        time.sleep(1)
    assert tested['tcp_ok'] and tested['udp_ok'],tested
    outside=row('foreign');assert outside['health']['tcp_ok'] and outside['health']['udp_ok']
    logs=api(url,{'id':rid,'action':'logs'});assert logs['ok'] and logs['cursor'] and logs['lines'],logs
    assert 'external-socks-password' not in json.dumps(logs) and 'external-fixture-key-' not in json.dumps(logs)
    # A real failed engine restart must restore exact vendor bytes and recover.
    r=row('iran');cfg=r['config'];cfg['network']['interface']='badnicfixture'
    try:api(url,{'id':rid,'action':'edit','revision':r['revision'],'config':cfg})
    except urllib.error.HTTPError as e:assert e.code==400
    else:raise AssertionError('invalid real NIC unexpectedly stayed active')
    assert execute('iran','cat',files['iran'])==before['iran']['config']
    execute('iran','systemctl','is-active',units['iran'])
    execute('iran','test','!','-e','/var/lib/donino-control/import-edit.json')
    # Check the original file secret survives redacted editing.
    r=row('iran');cfg=r['config'];cfg['log']['level']='warn'
    saved=api(url,{'id':rid,'action':'edit','revision':r['revision'],'config':cfg});assert saved['backup_saved'] and saved['restarted']
    actual=json.loads(execute('iran','cat',files['iran']))
    assert actual['transport']['kcp']['key']=='external-fixture-key-123456789012345'
    assert actual['socks5'][0]['password']=='external-socks-password'
    assert snapshot('foreign')==before['foreign'],'local edit changed foreign vendor service'
    logs2=api(url,{'id':rid,'action':'logs','cursor':logs['cursor']});assert logs2['ok'] and logs2['cursor']!=logs['cursor']
    # Panel upgrade must preserve both imported units/config/PIDs/firewall.
    pre_upgrade={n:snapshot(n) for n in units}
    for node in ('foreign','iran'):
        execute(node,'bash','/source/install-donino.sh','--upgrade')
        assert snapshot(node)==pre_upgrade[node],'panel upgrade altered vendor Paqet'
    for _ in range(30):
        try:login();foreign_login();api('/api/provision/state');foreign_api('/api/foreign/state');break
        except (OSError,AssertionError):time.sleep(1)
    else:raise AssertionError('panels did not recover after upgrade')
    # Give the upgraded peer responders a moment to start, then retest.
    for _ in range(12):
        tested=api(url,{'id':rid,'action':'test','profile_id':profile['id']})
        if tested['tcp_ok'] and tested['udp_ok']:break
        time.sleep(1)
    assert tested['tcp_ok'] and tested['udp_ok'],tested
    assert all(row(n)['management_enabled'] for n in units),'upgrade lost opt-in registry'
    assert not api('/api/status')['paths'] and not foreign_api('/api/status')['paths'],'detection activated another carrier'
    env={**os.environ,'DONINO_IRAN_URL':base,'DONINO_FOREIGN_URL':foreign_base}
    ui=subprocess.run(['node',str(Path(__file__).with_name('test-discovery-ui.cjs'))],capture_output=True,text=True,env=env,timeout=120)
    if ui.returncode:raise AssertionError('existing Paqet UI failed: '+ui.stdout[-3000:]+ui.stderr[-4000:])
    print(ui.stdout)
    # Explicit fixture cleanup; production discovery never runs this.
    for node in units:
        execute(node,'systemctl','disable','--now',units[node])
        execute(node,'rm','/etc/systemd/system/'+units[node]);execute(node,'systemctl','daemon-reload')
    execute('foreign','/opt/donino-link/current/venv/bin/python','-m','donino_link.raw_rules','remove','--peer',ips['iran'],'--port','33535')
    return {'independent_yaml_custom_units_detected_on_both_roles':True,'passive_scan_and_adoption_preserve_pid_config_firewall':True,
            'unadopted_control_rejected':True,'signed_tcp_and_socks_udp_roundtrips':True,'fresh_health_published_to_foreign':True,
            'live_journal_cursor_and_secret_redaction':True,'actual_failed_restart_restores_exact_original_yaml':True,
            'redacted_edit_preserves_original_secrets':True,'panel_upgrade_preserves_vendor_installation_and_grants':True,
            'no_other_carrier_activated':True,'real_browser_both_roles':True}
