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
from donino_link.browser import BrowserClient, BrowserServer, Credits, WINDOW
from donino_link.plan import make_plan
from donino_link.health import start_responder, probe

async def test(chromium, output, root_fixture):
    with tempfile.TemporaryDirectory(prefix='donino-browser-test-') as tmp:
        root=Path(tmp)
        plan=root/'plan'
        # Different fixed ports from the conventional engine integration suite.
        make_plan(plan,'127.0.0.1','127.0.0.1',[{'id':'echo','listen':'127.0.0.1:20190','target':'127.0.0.1:20191'},{'id':'delayed','listen':'127.0.0.1:20193','target':'127.0.0.1:20194'}],['browser-wss'],'browser-test-password-123',True,base=33000,carrier_base=36443,health_port=20192)
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
            finally:w.close();await w.wait_closed();tasks.discard(task)
        async def delayed(r,w):
            task=asyncio.current_task();tasks.add(task)
            try:
                payload=await r.read();await asyncio.sleep(.05);w.write(hashlib.sha256(payload).digest());await w.drain();w.write_eof()
            finally:w.close();await w.wait_closed();tasks.discard(task)
        echo_server=await asyncio.start_server(echo,'127.0.0.1',20191)
        delayed_server=await asyncio.start_server(delayed,'127.0.0.1',20194)
        key=json.loads((plan/'iran/node.json').read_text())['health_key']
        health=await start_responder('127.0.0.1:20192',key,{'echo':'127.0.0.1:20191'})
        try:
            await server.start();await client.start()
            await asyncio.wait_for(client.ready.wait(),30)
            ctx=ssl.create_default_context(cafile=str(plan/'iran/certs/ca.crt'))
            async with ClientSession() as session:
                for cookie,origin,service in [('',configs['foreign']['origin'],'echo'),(configs['foreign']['token'],'https://wrong.invalid','echo'),(configs['foreign']['token'],configs['foreign']['origin'],'not-allowed')]:
                    async with session.get(configs['foreign']['origin']+'/api/stream/'+service,ssl=ctx,headers={'Origin':origin,'Cookie':'donino_session='+cookie}) as resp:assert resp.status==404
            async def transfer(size):
                r,w=await asyncio.open_connection('127.0.0.1',33000)
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
            result={'scope':'Linux amd64 loopback; native Chromium; not an Iran DPI or WAN throughput test','chromium':Path(chromium).name,'concurrent_binary_echo':measurements,'health_probe_ms':round(latency,2),'half_close_delayed_response':True,'unauthorized_wrong_origin_unknown_target_rejected':True,'browser_crash_closes_stream_and_recovers':True,'max_streams':32,'flow_window_bytes_per_direction':32768*16}
            if output:Path(output).write_text(json.dumps(result,indent=2)+'\n')
            print(json.dumps(result,indent=2))
        finally:
            await client.stop();await server.stop()
            for s in [echo_server,delayed_server,health]:s.close();await s.wait_closed()
            for t in list(tasks):t.cancel()
            await asyncio.gather(*tasks,return_exceptions=True)

p=argparse.ArgumentParser();p.add_argument('--chromium',default='/usr/bin/chromium');p.add_argument('--output');p.add_argument('--root-test-fixture',action='store_true')
a=p.parse_args();asyncio.run(test(a.chromium,a.output,a.root_test_fixture))
