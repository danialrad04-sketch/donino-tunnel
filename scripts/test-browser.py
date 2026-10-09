#!/usr/bin/env python3
"""Real native Chromium transport test; loopback only, no firewall claims."""
import contextlib
import argparse
import asyncio
import hashlib
import json
import os
import ssl
import tempfile
import time
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from aiohttp import ClientSession
from donino_link.browser import BrowserClient, BrowserServer
from donino_link.artifacts import install_engines
from donino_link.gateway import Gateway
from donino_link.store import Store
from donino_link.framed import FramedRelay
from donino_link.plan import make_plan
from donino_link.health import start_responder, probe

async def test(chromium, output, root_fixture, binary_dir=None):
    with tempfile.TemporaryDirectory(prefix='donino-browser-test-') as tmp:
        root=Path(tmp)
        plan=root/'plan'
        # Different fixed ports from the conventional engine integration suite.
        make_plan(plan,'127.0.0.1','127.0.0.1',[{'id':'echo','listen':'127.0.0.1:20190','target':'127.0.0.1:20191'},{'id':'delayed','listen':'127.0.0.1:20193','target':'127.0.0.1:20194'}],['browser-wss','frp-quic'],'browser-test-password-123',True,base=33000,carrier_base=36443,health_port=20192)
        binaries=Path(binary_dir).resolve() if binary_dir else root/'bin'
        if not binary_dir:
            await asyncio.to_thread(install_engines,['frp'],binaries)
        engine_env={k:v for k,v in os.environ.items() if k.lower() not in ('http_proxy','https_proxy','all_proxy')}
        for role in ['iran','foreign']:
            file=plan/role/'transports/frp-quic.toml'
            file.write_text(file.read_text().replace('/etc/donino-link/current',str(plan/role)))
        gateway_config=json.loads((plan/'iran/node.json').read_text())
        gateway_config['state_db']=str(root/'state.sqlite3')
        gateway_config['policy'].update(probe_interval=.2,probe_timeout=1,failures=2,recoveries=2)
        store=Store(gateway_config['state_db']);gateway=Gateway(gateway_config,store)
        relays=[FramedRelay(json.loads((plan/role/"transports/framed.json").read_text())) for role in ["iran","foreign"]]
        engines=[]
        configs={}
        for role in ['iran','foreign']:
            configs[role]=json.loads((plan/role/'transports/browser-wss.json').read_text().replace('/etc/donino-link/current',str(plan/role)))
        configs['foreign']['listen']='127.0.0.1:36443'
        configs['iran']['chromium']=str(Path(chromium).resolve())
        if root_fixture:
            configs['iran']['test_no_sandbox']=True
            os.environ['DONINO_TEST']='1'
        server=BrowserServer(configs['foreign']);client=BrowserClient(configs['iran'])
        tasks=set()
        async def echo(r,w):
            task=asyncio.current_task();tasks.add(task)
            try:
                while b:=await r.read(65536):w.write(b);await w.drain()
                w.write_eof()
            except OSError:pass
            finally:
                w.close()
                with contextlib.suppress(OSError):await w.wait_closed()
                tasks.discard(task)
        async def delayed(r,w):
            task=asyncio.current_task();tasks.add(task)
            try:
                payload=await r.read();await asyncio.sleep(.05);w.write(hashlib.sha256(payload).digest());await w.drain();w.write_eof()
            except OSError:pass
            finally:
                w.close()
                with contextlib.suppress(OSError):await w.wait_closed()
                tasks.discard(task)
        echo_server=await asyncio.start_server(echo,'127.0.0.1',20191)
        delayed_server=await asyncio.start_server(delayed,'127.0.0.1',20194)
        key=json.loads((plan/'iran/node.json').read_text())['health_key']
        health=await start_responder('127.0.0.1:20192',key,{'echo':'127.0.0.1:20191'})
        try:
            for relay in relays:await relay.start()
            for role in ['iran','foreign']:
                binary='frps' if role=='iran' else 'frpc'
                engines.append(await asyncio.create_subprocess_exec(str(binaries/binary),'-c',str(plan/role/'transports/frp-quic.toml'),stdout=asyncio.subprocess.DEVNULL,stderr=asyncio.subprocess.DEVNULL,env=engine_env))
            await server.start();await client.start()
            await asyncio.wait_for(client.ready.wait(),30)
            ctx=ssl.create_default_context(cafile=str(plan/'iran/certs/ca.crt'))
            async with ClientSession() as session:
                for cookie,origin,service in [('',configs['foreign']['origin'],'echo'),(configs['foreign']['token'],'https://wrong.invalid','echo'),(configs['foreign']['token'],configs['foreign']['origin'],'not-allowed')]:
                    async with session.get(configs['foreign']['origin']+'/api/stream/'+service,ssl=ctx,headers={'Origin':origin,'Cookie':'donino_session='+cookie}) as resp:assert resp.status==404
            async def transfer(size,port=33000):
                r,w=await asyncio.open_connection('127.0.0.1',port)
                payload=os.urandom(size);start=time.monotonic()
                async def upload():w.write(payload);await w.drain();w.write_eof()
                sending=asyncio.create_task(upload())
                try:
                    result=await asyncio.wait_for(r.read(),30);await sending
                    assert result==payload,'binary payload mismatch or truncated EOF'
                    return {'bytes_each_direction':size,'seconds':round(time.monotonic()-start,3),'sha256_match':True}
                finally:
                    sending.cancel();await asyncio.gather(sending,return_exceptions=True);w.close()
                    with contextlib.suppress(OSError):await w.wait_closed()
            measurements=await asyncio.gather(transfer(4*1024*1024),transfer(2*1024*1024))
            r,w=await asyncio.open_connection('127.0.0.1',33001)
            payload=os.urandom(128*1024);w.write(payload);await w.drain();w.write_eof()
            assert await asyncio.wait_for(r.read(),10)==hashlib.sha256(payload).digest()
            w.close();await w.wait_closed()
            latency,_=await probe('127.0.0.1:33050',key,5)
            # A browser crash must close current streams and permit a fresh,
            # authenticated browser session, without replaying client bytes.
            old=client.process.pid
            r,w=await asyncio.open_connection('127.0.0.1',33000)
            w.write(b'before-crash');await w.drain();assert await asyncio.wait_for(r.readexactly(12),5)==b'before-crash'
            client.process.terminate()
            assert await asyncio.wait_for(r.read(),10)==b''
            w.close();await w.wait_closed()
            for _ in range(200):
                if client.ready.is_set() and client.process and client.process.pid!=old:break
                await asyncio.sleep(.05)
            else:raise AssertionError('browser did not restart')
            await probe('127.0.0.1:33050',key,5)
            await gateway.start()
            for _ in range(100):
                if all(p.healthy for p in gateway.paths.values()):break
                await asyncio.sleep(.1)
            else:raise AssertionError('browser and real QUIC did not become healthy')
            await transfer(256*1024,20190)
            assert gateway.last_path=='browser-wss'
            await client.stop()
            for _ in range(100):
                if not gateway.paths['browser-wss'].healthy:break
                await asyncio.sleep(.1)
            else:raise AssertionError('browser path failure detection timed out')
            await transfer(256*1024,20190)
            assert gateway.last_path=='frp-quic','native browser failure did not select actual QUIC carrier'
            client=BrowserClient(configs['iran']);await client.start()
            await asyncio.wait_for(client.ready.wait(),30)
            for _ in range(100):
                if gateway.paths['browser-wss'].healthy:break
                await asyncio.sleep(.1)
            else:raise AssertionError('browser path did not recover')
            await transfer(256*1024,20190)
            assert gateway.last_path=='browser-wss'
            result={'gateway_failover_to_real_quic_and_recovery':True,'scope':'Linux amd64 loopback; native Chromium; not an Iran DPI or WAN throughput test','chromium':Path(chromium).name,'concurrent_binary_echo':measurements,'health_probe_ms':round(latency,2),'half_close_delayed_response':True,'unauthorized_wrong_origin_unknown_target_rejected':True,'browser_crash_closes_stream_and_recovers':True,'max_streams':32,'flow_window_bytes_per_direction':32768*16}
            if output:Path(output).write_text(json.dumps(result,indent=2)+'\n')
            print(json.dumps(result,indent=2))
        finally:
            await gateway.stop();store.close()
            for relay in relays:await relay.stop()
            await client.stop();await server.stop()
            for process in engines:
                if process.returncode is None:process.terminate()
            await asyncio.gather(*(process.wait() for process in engines),return_exceptions=True)
            for s in [echo_server,delayed_server,health]:s.close();await s.wait_closed()
            for t in list(tasks):t.cancel()
            await asyncio.gather(*tasks,return_exceptions=True)

p=argparse.ArgumentParser();p.add_argument('--chromium',default='/usr/bin/chromium');p.add_argument('--output');p.add_argument('--root-test-fixture',action='store_true');p.add_argument('--binary-dir')
a=p.parse_args();asyncio.run(test(a.chromium,a.output,a.root_test_fixture,a.binary_dir))
