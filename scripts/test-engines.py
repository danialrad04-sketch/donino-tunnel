#!/usr/bin/env python3
"""Real loopback engine tests. Never change host firewall or deploy to servers."""
import argparse
import asyncio
import hashlib
import json
import os
import subprocess
import signal
import ssl
import tempfile
import time
import resource
from pathlib import Path
from donino_link.plan import make_plan
from donino_link.health import start_responder,probe
from donino_link.tlsfront import TLSFront
from donino_link.gateway import Gateway
from donino_link.store import Store
from donino_link.framed import FramedRelay
from donino_link.artifacts import install_engines
from donino_link.datagram import DatagramRelay, Protocol


async def test(binary_dir, output, serve_panel=False):
    with tempfile.TemporaryDirectory(prefix='donino-integration-') as temp:
        root=Path(temp)
        if binary_dir:
            binaries=Path(binary_dir).resolve()
        else:
            binaries=root/'bin'
            await asyncio.to_thread(install_engines,['frp','backpack','backhaul'],binaries)
        transports=['frp-wss','frp-quic','backpack-wss','backhaul-wss']
        plan=root/'plan'
        services=[{'id':'echo','listen':'127.0.0.1:19990','target':'127.0.0.1:19991'},
                  {'id':'datagram','listen':'127.0.0.1:19993','target':'127.0.0.1:19994','protocol':'udp'}]
        make_plan(plan,'127.0.0.1','127.0.0.1',services,transports,'integration-only-password-123',True,base=32000,carrier_base=34443,health_port=19992)
        for role in ['iran','foreign']:
            for file in (plan/role/'transports').glob('*.toml'):
                file.write_text(file.read_text().replace('/etc/donino-link/current',str(plan/role)).replace('bind_addr = "0.0.0.0:','bind_addr = "127.0.0.1:').replace('bindAddr = "0.0.0.0"','bindAddr = "127.0.0.1"'))
        config=json.loads((plan/'iran/node.json').read_text())
        config['policy'].update(probe_interval=.2,probe_timeout=1,failures=2,recoveries=2)
        config['state_db']=str(root/'state.sqlite3')
        key=config['health_key']
        processes=[]
        logs=[]
        # FRP adopts proxy environment variables; loopback tests must stay local.
        engine_env={k:v for k,v in os.environ.items() if k.lower() not in ('http_proxy','https_proxy','all_proxy')}
        front=TLSFront('127.0.0.1:34443','127.0.0.1:35443',plan/'iran/certs/server.crt',plan/'iran/certs/server.key',plan/'iran/certs/ca.crt')
        store=Store(config['state_db'])
        gateway=Gateway(config,store)
        echo_tasks=set()
        async def echo(reader,writer):
            task=asyncio.current_task();echo_tasks.add(task)
            try:
                # Wait for EOF before responding: carriers must preserve the
                # logical half-close, not merely echo a still-open stream.
                data=await reader.read()
                writer.write(data);await writer.drain()
            except OSError:pass
            finally:writer.close();await writer.wait_closed();echo_tasks.discard(task)
        echo_server=await asyncio.start_server(echo,'127.0.0.1',19991)
        health=await start_responder('127.0.0.1:19992',key,{'echo':'127.0.0.1:19991'})
        udp_origin=None
        def udp_echo(data,address):udp_origin.sendto(data,address)
        udp_origin,_=await asyncio.get_running_loop().create_datagram_endpoint(lambda:Protocol(udp_echo),local_addr=('127.0.0.1',19994))
        udp_relay=DatagramRelay('datagram','127.0.0.1:34001','127.0.0.1:19994',key)
        relays=[FramedRelay(json.loads((plan/role/"transports/framed.json").read_text())) for role in ["iran","foreign"]]
        results={}
        start=time.monotonic()
        async def transfer(address,size=2*1024*1024):
            reader,writer=await asyncio.open_connection('127.0.0.1',address)
            payload=os.urandom(size)
            async def send():writer.write(payload);await writer.drain();writer.write_eof()
            sending=asyncio.create_task(send())
            try:
                response=await asyncio.wait_for(reader.readexactly(size),15)
                await sending
                assert hashlib.sha256(response).digest()==hashlib.sha256(payload).digest(),'payload mismatch'
                return size
            finally:
                sending.cancel();await asyncio.gather(sending,return_exceptions=True)
                writer.close();await writer.wait_closed()
        try:
            await udp_relay.start()
            for relay in relays:await relay.start()
            await front.start()
            # A correct server CA without a client certificate is insufficient.
            no_client=ssl.create_default_context(cafile=str(plan/'iran/certs/ca.crt'))
            unauthorized=None
            rejected=False
            try:
                ur,unauthorized=await asyncio.open_connection('127.0.0.1',34443,ssl=no_client,server_hostname='127.0.0.1')
                unauthorized.write(b'GET /~!frp HTTP/1.1\r\nHost: localhost\r\n\r\n')
                await unauthorized.drain()
                data=await asyncio.wait_for(ur.read(64),2)
                rejected=not data
            except (ssl.SSLError,ConnectionError):rejected=True
            finally:
                if unauthorized:
                    unauthorized.close()
                    try:await unauthorized.wait_closed()
                    except (ssl.SSLError,ConnectionError):pass
            assert rejected,'mTLS front accepted a client without a certificate'
            results['mtls_front_requires_client_certificate']=True
            for i,t in enumerate(transports):
                for role in ['iran','foreign']:
                    binary=('frps' if role=='iran' else 'frpc') if t.startswith('frp') else t.split('-')[0]
                    file=plan/role/'transports'/f'{t}.toml'
                    if t.startswith('frp'):
                        subprocess.run([str(binaries/binary),'verify','-c',str(file)],check=True,stdout=subprocess.DEVNULL)
                    log=open(root/f'{t}-{role}.log','w+');logs.append(log)
                    processes.append((t,role,subprocess.Popen([str(binaries/binary),'-c',str(file)],stdout=log,stderr=log,env=engine_env)))
                for _ in range(40):
                    await asyncio.sleep(.25)
                    try:
                        ms,_=await probe(f'127.0.0.1:{32050+i*100}',key,1)
                        break
                    except (OSError,ValueError,asyncio.TimeoutError):pass
                else:raise AssertionError(t+' did not pass authenticated probe')
                transferred=await transfer(32060+i*100)
                results[t]={'probe_ms':round(ms,3),'bytes_echoed':transferred,'binary_payload_sha256_match':True,'half_close_preserved':True,'response_after_upload_eof':True}
                print(t,'PASS',flush=True)
            await gateway.start()
            for _ in range(30):
                await asyncio.sleep(.2)
                if all(p.healthy for p in gateway.paths.values()):break
            else:raise AssertionError('gateway did not see all paths healthy')
            await transfer(19990,512*1024)
            assert gateway.last_path=='frp-wss'
            responses=asyncio.Queue()
            udp_client,_=await asyncio.get_running_loop().create_datagram_endpoint(
                lambda:Protocol(lambda data,address:responses.put_nowait(data)),remote_addr=('127.0.0.1',19993))
            try:
                for transport in transports:
                    gateway.action(transport,'prefer')
                    payload=os.urandom(1200)
                    udp_client.sendto(payload)
                    assert await asyncio.wait_for(responses.get(),5)==payload
                    results[transport]['udp_payload_sha256_match']=True
                gateway.action('frp-wss','prefer')
                udp_client.sendto(b'before-real-carrier-loss')
                assert await asyncio.wait_for(responses.get(),5)==b'before-real-carrier-loss'
            except BaseException:
                udp_client.close()
                raise
            gateway.action(None,'auto')
            # Mixed local workload: 50 concurrent TCP transfers and 50 distinct
            # UDP associations through the real encrypted WSS engine. This is
            # a bounded echo workload, not 50 VPN users or a WAN benchmark.
            load_started=time.monotonic();cpu_started=time.process_time();clients=[]
            try:
                for index in range(50):
                    queue=asyncio.Queue()
                    transport,_=await asyncio.get_running_loop().create_datagram_endpoint(
                        lambda queue=queue:Protocol(lambda data,address:queue.put_nowait(data)),
                        remote_addr=('127.0.0.1',19993))
                    clients.append((transport,queue))
                async def mixed(index,client):
                    transport,queue=client
                    for round_number in range(2):
                        packet=index.to_bytes(2,'big')+bytes([round_number])*1198
                        transport.sendto(packet)
                        assert await asyncio.wait_for(queue.get(),5)==packet
                        await transfer(19990,64*1024)
                await asyncio.gather(*(mixed(i,c) for i,c in enumerate(clients)))
                results['mixed_load']={'scope':'loopback echo through real FRP WSS; no VPN backend or WAN load',
                    'concurrent_clients':50,'tcp_transfers':100,'udp_associations':50,'udp_messages':100,
                    'tcp_bytes_each_direction':100*64*1024,'udp_payload_bytes':1200,
                    'wall_seconds':round(time.monotonic()-load_started,3),
                    'controller_cpu_seconds':round(time.process_time()-cpu_started,3),
                    'controller_max_rss_mib':round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1024,2),
                    'available_cpu_cores':len(os.sched_getaffinity(0)),'all_payloads_match':True}
            finally:
                for transport,_ in clients:transport.close()
            # Real transport loss, not a mocked health flag.
            for t,role,pr in processes:
                if t=='frp-wss':pr.terminate();await asyncio.to_thread(pr.wait,5)
            await front.stop()
            for _ in range(40):
                await asyncio.sleep(.2)
                if not gateway.paths['frp-wss'].healthy:break
            assert not gateway.paths['frp-wss'].healthy,'failure detection timed out'
            await transfer(19990,512*1024)
            assert gateway.last_path=='frp-quic','expected independent QUIC failover'
            udp_client.sendto(b'after-real-carrier-loss')
            assert await asyncio.wait_for(responses.get(),5)==b'after-real-carrier-loss'
            udp_client.close()
            assert len(udp_relay.flows)==51,'UDP migration reopened the foreign association'
            results['udp_failover']={'from':'frp-wss','to':'frp-quic','same_origin_association':True,'pass':True}
            results['failover']={'from':'frp-wss','to':'frp-quic','bytes_echoed':512*1024,'pass':True}
            results['elapsed_seconds']=round(time.monotonic()-start,2)
            results['scope']='loopback Linux, amd64; no Iran route, raw packets or production load test'
            print('REAL TRANSPORT FAILOVER PASS',flush=True)
            if output:
                Path(output).write_text(json.dumps(results,indent=2)+'\n')
            if serve_panel:
                from donino_link.panel import Panel
                config['panel'].update(listen='127.0.0.1:18090',credentials_file=str(plan/'iran/admin.json'),api_token_file=str(plan/'iran/api-token'))
                panel=Panel(gateway)
                await panel.start()
                stop=asyncio.Event()
                for sig in [signal.SIGTERM,signal.SIGINT]:asyncio.get_running_loop().add_signal_handler(sig,stop.set)
                print('LOCAL INTEGRATION PANEL READY http://127.0.0.1:18090',flush=True)
                try:await stop.wait()
                finally:await panel.stop()
        except BaseException:
            for log in logs:
                log.flush();log.seek(0);print(log.name,log.read()[-2500:])
            raise
        finally:
            await gateway.stop();store.close()
            await udp_relay.stop()
            if udp_origin:udp_origin.close()
            for relay in relays:await relay.stop()
            await front.stop()
            for _,_,pr in processes:
                if pr.poll() is None:pr.terminate()
            for _,_,pr in processes:
                try:await asyncio.to_thread(pr.wait,5)
                except subprocess.TimeoutExpired:pr.kill();await asyncio.to_thread(pr.wait)
            health.close();echo_server.close()
            await health.wait_closed();await echo_server.wait_closed()
            for task in list(echo_tasks):task.cancel()
            await asyncio.gather(*echo_tasks,return_exceptions=True)
            for log in logs:log.close()
        if output:
            Path(output).write_text(json.dumps(results,indent=2)+'\n')
        print(json.dumps(results,indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--binary-dir');p.add_argument('--output');p.add_argument('--serve-panel',action='store_true');p.add_argument('--one-core',action='store_true')
    a=p.parse_args()
    if a.one_core:
        os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
        resource.setrlimit(resource.RLIMIT_AS,(1024**3,1024**3))
    asyncio.run(test(a.binary_dir,a.output,a.serve_panel))
