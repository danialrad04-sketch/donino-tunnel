"""mTLS TCP front for FRP's loopback WebSocket listener.

FRP WSS clients negotiate TLS before HTTP. The stock frps listener expects
WebSocket before optional inner TLS, so the two need a TLS termination front.
This front carries the decrypted HTTP/WebSocket stream only to loopback frps.
"""
import argparse
import asyncio
import contextlib
import signal
import ssl
import sys
from .config import endpoint,loopback


class TLSFront:
    def __init__(self, listen, upstream, cert, key, ca, limit=1024):
        if not loopback(upstream):
            raise ValueError('TLS front upstream must be literal loopback')
        self.listen,self.upstream=listen,upstream
        self.context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version=ssl.TLSVersion.TLSv1_2
        self.context.load_cert_chain(cert,key)
        self.context.load_verify_locations(cafile=ca)
        self.context.verify_mode=ssl.CERT_REQUIRED
        self.limit=limit
        self.connections=set()
        self.server=None

    async def handle(self,reader,writer):
        task=asyncio.current_task()
        remote=None
        tasks=[]
        if len(self.connections)>=self.limit:
            writer.close();return
        self.connections.add(task)
        try:
            rr,remote=await asyncio.wait_for(asyncio.open_connection(*endpoint(self.upstream)),3)
            async def pump(r,w):
                while data:=await asyncio.wait_for(r.read(65536),300):
                    w.write(data);await w.drain()
            tasks=[asyncio.create_task(pump(reader,remote)),asyncio.create_task(pump(rr,writer))]
            done,_=await asyncio.wait(tasks,return_when=asyncio.FIRST_COMPLETED)
            for t in done:t.result()
        except (OSError,asyncio.TimeoutError):
            pass
        finally:
            for t in tasks:t.cancel()
            await asyncio.gather(*tasks,return_exceptions=True)
            for w in [remote,writer]:
                if w:
                    w.close()
                    with contextlib.suppress(OSError):await w.wait_closed()
            self.connections.discard(task)

    async def start(self):
        options={'ssl_handshake_timeout':10}
        # ssl_shutdown_timeout was added in Python 3.11. Ubuntu 22 uses 3.10.
        if sys.version_info >= (3,11):options['ssl_shutdown_timeout']=5
        self.server=await asyncio.start_server(self.handle,*endpoint(self.listen),ssl=self.context,
                                               **options)

    async def stop(self):
        if self.server:
            self.server.close();await self.server.wait_closed()
        for task in list(self.connections):task.cancel()
        await asyncio.gather(*self.connections,return_exceptions=True)


async def serve(args):
    front=TLSFront(args.listen,args.upstream,args.cert,args.key,args.ca)
    done=asyncio.Event()
    for sig in [signal.SIGTERM,signal.SIGINT]:asyncio.get_running_loop().add_signal_handler(sig,done.set)
    try:
        await front.start();await done.wait()
    finally:
        await front.stop()


def main():
    p=argparse.ArgumentParser()
    for key in ['listen','upstream','cert','key','ca']:p.add_argument('--'+key,required=True)
    asyncio.run(serve(p.parse_args()))


if __name__=='__main__':main()
