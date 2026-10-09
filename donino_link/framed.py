"""Bounded stream framing over existing encrypted carriers.

Logical EOF never half-closes the carrier socket. Both directions can finish
independently even when an underlying proxy does not preserve TCP half-close.
All listeners and destinations are private loopback; carrier owns encryption.
"""
import argparse
import asyncio
import contextlib
import ipaddress
import json
import signal
import struct
import time
from pathlib import Path
from .config import endpoint

CHUNK=32768
HEADER=struct.Struct('!BI')


async def frame(reader):
    kind,size=HEADER.unpack(await reader.readexactly(HEADER.size))
    if kind==0 and 0<size<=CHUNK:
        return await reader.readexactly(size)
    if kind==1 and size==0:
        return None
    raise ValueError('invalid stream frame')


class FramedRelay:
    def __init__(self,config):
        self.config=config
        self.servers=[]
        self.tasks=set()

    async def handle(self,reader,writer,target):
        task=asyncio.current_task();self.tasks.add(task)
        upstream=None;workers=[]
        try:
            if len(self.tasks)>1024:
                return
            remote,upstream=await asyncio.wait_for(asyncio.open_connection(*endpoint(target)),5)
            # Iran accepts plain TCP; foreign accepts framed carrier bytes.
            plain_reader,plain_writer,wire_reader,wire_writer=(reader,writer,remote,upstream) if self.config['role']=='iran' else (remote,upstream,reader,writer)
            activity=[time.monotonic()]
            async def encode():
                while block:=await plain_reader.read(CHUNK):
                    activity[0]=time.monotonic()
                    wire_writer.write(HEADER.pack(0,len(block))+block)
                    await wire_writer.drain()
                wire_writer.write(HEADER.pack(1,0))
                await wire_writer.drain()
            async def decode():
                while True:
                    block=await frame(wire_reader)
                    activity[0]=time.monotonic()
                    if block is None:
                        plain_writer.write_eof();await plain_writer.drain()
                        return
                    plain_writer.write(block);await plain_writer.drain()
            async def guard():
                while True:
                    await asyncio.sleep(5)
                    if time.monotonic()-activity[0]>=300:
                        raise TimeoutError('idle framed stream')
            workers=[asyncio.create_task(encode()),asyncio.create_task(decode()),asyncio.create_task(guard())]
            pending=set(workers[:2])
            while pending:
                done,_=await asyncio.wait(pending|{workers[2]},return_when=asyncio.FIRST_COMPLETED)
                for finished in done:finished.result()
                pending-=done
        except (OSError,ValueError,asyncio.IncompleteReadError,asyncio.TimeoutError):
            pass
        finally:
            for worker in workers:worker.cancel()
            await asyncio.gather(*workers,return_exceptions=True)
            for stream in [writer,upstream]:
                if stream:
                    stream.close()
                    with contextlib.suppress(OSError):await stream.wait_closed()
            self.tasks.discard(task)

    async def start(self):
        if self.config['role'] not in ('iran','foreign'):
            raise ValueError('invalid relay role')
        for item in self.config['listeners']:
            for address in [item['listen'],item['target']]:
                if not ipaddress.ip_address(endpoint(address)[0]).is_loopback:
                    raise ValueError('framed relay endpoints must be literal loopback addresses')
        try:
            for item in self.config['listeners']:
                self.servers.append(await asyncio.start_server(lambda r,w,t=item['target']:self.handle(r,w,t),*endpoint(item['listen'])))
        except BaseException:
            await self.stop();raise

    async def stop(self):
        for server in self.servers:server.close()
        await asyncio.gather(*(server.wait_closed() for server in self.servers))
        for task in list(self.tasks):task.cancel()
        await asyncio.gather(*self.tasks,return_exceptions=True)
        self.servers.clear()


async def run(config):
    relay=FramedRelay(config);done=asyncio.Event()
    for sig in [signal.SIGTERM,signal.SIGINT]:asyncio.get_running_loop().add_signal_handler(sig,done.set)
    try:await relay.start();await done.wait()
    finally:await relay.stop()

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--config',required=True)
    args=p.parse_args();asyncio.run(run(json.loads(Path(args.config).read_text())))
