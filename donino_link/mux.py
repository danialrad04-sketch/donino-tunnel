"""Donino Mux v1: authenticated WSS sessions with bounded stream credits.

An application protocol, not new cryptography or a claim of DPI invisibility.
Each stream stays on one session; disconnected streams are never replayed.
"""
import argparse
import asyncio
import contextlib
import ipaddress
import json
import re
import signal
import ssl
import struct
import time
from collections import deque
from pathlib import Path
from aiohttp import web,ClientSession,ClientTimeout,WSMsgType,ClientError
from .config import endpoint
from .runtime import RuntimeStats

PROTOCOL='donino-mux.v1'
HEADER=struct.Struct('!BII')
CREDIT=struct.Struct('!IH')
CHUNK=16384
WINDOW=262144
SLOTS=16
STREAMS=32
HELLO,OPEN,READY,DATA,UPDATE,FIN,RESET=range(7)
GREETING=struct.pack('!4sIHH',b'DMX1',WINDOW,CHUNK,STREAMS)
NAME=re.compile(r'[a-z][a-z0-9-]{0,31}\Z')


def packet(kind,sid,payload=b''):
    return HEADER.pack(kind,sid,len(payload))+payload


def unpack(raw):
    if not isinstance(raw,bytes) or len(raw)<HEADER.size:raise ValueError('short mux frame')
    kind,sid,size=HEADER.unpack(raw[:HEADER.size]);body=raw[HEADER.size:]
    if size!=len(body) or size>CHUNK or kind not in range(7):raise ValueError('invalid mux frame')
    if kind==HELLO:
        if sid or body!=GREETING:raise ValueError('unsupported mux version or limits')
    elif not sid or sid%2==0:raise ValueError('invalid stream ID')
    elif kind==OPEN:
        if not NAME.fullmatch(body.decode('ascii')):raise ValueError('invalid service name')
    elif kind in (READY,FIN,RESET):
        if body:raise ValueError('unexpected frame payload')
    elif kind==DATA:
        if not body:raise ValueError('empty data frame')
    elif kind==UPDATE:
        if len(body)!=CREDIT.size:raise ValueError('invalid credit frame')
        credit,slots=CREDIT.unpack(body)
        if not 0<credit<=WINDOW or not 0<slots<=SLOTS:raise ValueError('invalid credit increment')
    return kind,sid,body


def tls_context(config,server=False):
    ctx=ssl.create_default_context(ssl.Purpose.CLIENT_AUTH if server else ssl.Purpose.SERVER_AUTH,cafile=config['ca'])
    ctx.minimum_version=ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(config['cert'],config['key']);ctx.verify_mode=ssl.CERT_REQUIRED
    ctx.set_alpn_protocols(['http/1.1'])
    return ctx


async def close_writer(writer,timeout=5):
    """Do not keep a retired stream alive when a TCP peer stops reading."""
    writer.close()
    try:await asyncio.wait_for(writer.wait_closed(),timeout)
    except (OSError,asyncio.TimeoutError):writer.transport.abort()
    except asyncio.CancelledError:
        writer.transport.abort();raise


class Stream:
    def __init__(self,session,sid,service,reader=None,writer=None):
        self.session,self.sid,self.service=session,sid,service
        self.reader,self.writer=reader,writer
        self.credit,self.slots=WINDOW,SLOTS
        self.rx_credit,self.rx_slots=WINDOW,SLOTS
        self.condition=asyncio.Condition();self.incoming=asyncio.Queue(maxsize=SLOTS+1)
        self.ready=asyncio.get_running_loop().create_future()
        self.local_fin=self.remote_fin=self.received_fin=self.closed=False
        self.activity=time.monotonic();self.task=None;self.counted=False

    async def produce(self):
        while True:
            async with self.condition:
                await self.condition.wait_for(lambda:self.closed or (self.credit>0 and self.slots>0))
                if self.closed:return
                allowance=min(CHUNK,self.credit)
            block=await self.reader.read(allowance)
            if not block:
                self.local_fin=True;await self.session.send(FIN,self.sid);return
            async with self.condition:
                self.credit-=len(block);self.slots-=1
            await self.session.send(DATA,self.sid,block);self.activity=time.monotonic()
            self.session.count(self,'read',len(block))

    async def consume(self):
        while True:
            block=await self.incoming.get()
            if block is None:
                if not self.writer.can_write_eof():raise ValueError('origin does not support half-close')
                self.writer.write_eof();await self.writer.drain();self.remote_fin=True;return
            self.writer.write(block);await self.writer.drain();self.activity=time.monotonic()
            self.session.count(self,'write',len(block))
            self.rx_credit+=len(block);self.rx_slots+=1
            await self.session.send(UPDATE,self.sid,CREDIT.pack(len(block),1))

    async def guard(self):
        while True:
            await asyncio.sleep(5)
            if time.monotonic()-self.activity>=self.session.node.idle_timeout:raise TimeoutError('idle mux stream')

    async def run(self):
        workers=[]
        try:
            await asyncio.wait_for(asyncio.shield(self.ready),self.session.node.connect_timeout)
            # Python 3.11 wait_for can return an already completed future when
            # cancellation races with READY. Never start workers after RESET.
            if self.closed or self.session.closed:return
            self.counted=self.service!='health'
            if self.counted:self.session.node.stats.active+=1;self.session.node.stats.accepted+=1
            workers=[asyncio.create_task(self.produce()),asyncio.create_task(self.consume()),asyncio.create_task(self.guard())]
            pending=set(workers[:2])
            while pending:
                done,_=await asyncio.wait(pending|{workers[2]},return_when=asyncio.FIRST_COMPLETED)
                for task in done:task.result()
                pending-=done
            async with self.condition:
                await asyncio.wait_for(self.condition.wait_for(lambda:self.closed or (self.credit==WINDOW and self.slots==SLOTS)),self.session.node.idle_timeout)
        except (OSError,ValueError,ClientError,asyncio.TimeoutError):
            if not self.closed:
                with contextlib.suppress(OSError,ClientError,asyncio.TimeoutError):await self.session.send(RESET,self.sid)
        finally:
            self.closed=True
            try:
                for worker in workers:worker.cancel()
                await asyncio.gather(*workers,return_exceptions=True)
            finally:
                try:
                    if self.writer:await close_writer(self.writer)
                finally:
                    self.session.retire(self.sid)
                    if self.counted:self.session.node.stats.active-=1


class Session:
    def __init__(self,node,ws):
        self.node,self.ws=node,ws
        self.streams={};self.retired=deque(maxlen=128);self.tasks=set()
        self.send_lock=asyncio.Lock();self.next_id=1;self.last_remote_id=0;self.closed=False

    def retire(self,sid):
        if self.streams.pop(sid,None) is not None:self.retired.append(sid)

    def spawn(self,coro):
        task=asyncio.create_task(coro);self.tasks.add(task);task.add_done_callback(self.tasks.discard)
        return task

    def count(self,stream,direction,size):
        if stream.service=='health':return
        up=(self.node.role=='iran' and direction=='read') or (self.node.role=='foreign' and direction=='write')
        if up:self.node.stats.bytes_up+=size
        else:self.node.stats.bytes_down+=size

    async def send(self,kind,sid,body=b''):
        if self.closed:raise ConnectionError('mux session disconnected')
        # FIFO asyncio lock, <=16 KiB data frames, explicit yield even when the
        # websocket's buffer is empty. Credit waits never hold the writer lock.
        async with self.send_lock:
            await asyncio.wait_for(self.ws.send_bytes(packet(kind,sid,body)),self.node.connect_timeout)
        await asyncio.sleep(0)

    async def open(self,service,reader,writer):
        limit=STREAMS if service=='health' else STREAMS-1
        if self.closed or len(self.streams)>=limit or self.next_id>0xffffffff:raise ConnectionError('mux lane at capacity')
        sid=self.next_id;self.next_id+=2
        stream=Stream(self,sid,service,reader,writer);self.streams[sid]=stream
        stream.task=self.spawn(stream.run())
        try:await self.send(OPEN,sid,service.encode('ascii'))
        except BaseException:
            stream.task.cancel();await asyncio.gather(stream.task,return_exceptions=True);raise
        return stream.task

    async def accept(self,stream):
        try:
            stream.reader,stream.writer=await asyncio.wait_for(asyncio.open_connection(*endpoint(self.node.targets[stream.service])),self.node.connect_timeout)
            if stream.closed or self.closed:return
            stream.ready.set_result(True)
            await self.send(READY,stream.sid)
            await stream.run()
        except (OSError,ClientError,asyncio.TimeoutError):
            with contextlib.suppress(OSError,ClientError,asyncio.TimeoutError):await self.send(RESET,stream.sid)
        finally:
            if self.streams.get(stream.sid) is stream:
                try:
                    if stream.writer:await close_writer(stream.writer)
                finally:self.retire(stream.sid)

    async def receive(self):
        try:
            async for message in self.ws:
                if message.type==WSMsgType.ERROR:
                    self.node.last_error=str(self.ws.exception());break
                if message.type==WSMsgType.CLOSED:break
                if message.type!=WSMsgType.BINARY:raise ValueError('mux requires binary frames')
                kind,sid,body=unpack(message.data)
                if kind==HELLO:raise ValueError('duplicate mux greeting')
                if kind==OPEN:
                    if self.node.role!='foreign' or sid<=self.last_remote_id:raise ValueError('invalid OPEN direction or reused ID')
                    self.last_remote_id=sid
                    service=body.decode('ascii')
                    limit=STREAMS if service=='health' else STREAMS-1
                    if service not in self.node.targets or len(self.streams)>=limit:
                        self.retired.append(sid);await self.send(RESET,sid);continue
                    stream=Stream(self,sid,service);self.streams[sid]=stream
                    stream.task=self.spawn(self.accept(stream));continue
                stream=self.streams.get(sid)
                if stream is None:
                    if sid in self.retired:continue # in-flight frames after reset
                    raise ValueError('unknown stream ID')
                if kind==READY:
                    if self.node.role!='iran' or stream.ready.done():raise ValueError('unexpected stream acceptance')
                    stream.ready.set_result(True)
                elif kind==RESET:
                    stream.closed=True;stream.task.cancel()
                elif not stream.ready.done():raise ValueError('stream not accepted')
                elif kind==DATA:
                    if stream.received_fin or len(body)>stream.rx_credit or stream.rx_slots<=0:raise ValueError('receive credit exceeded or data after FIN')
                    stream.rx_credit-=len(body);stream.rx_slots-=1;stream.incoming.put_nowait(body)
                elif kind==FIN:
                    if stream.received_fin:raise ValueError('duplicate FIN')
                    stream.received_fin=True;stream.incoming.put_nowait(None)
                elif kind==UPDATE:
                    credit,slots=CREDIT.unpack(body)
                    async with stream.condition:
                        if stream.credit+credit>WINDOW or stream.slots+slots>SLOTS:raise ValueError('send credit overflow')
                        stream.credit+=credit;stream.slots+=slots;stream.condition.notify_all()
        except (OSError,ClientError,ValueError,UnicodeError,struct.error,asyncio.QueueFull) as error:
            self.node.last_error=type(error).__name__+': '+str(error)
        finally:await self.close()

    async def close(self):
        if self.closed:return
        self.closed=True
        tasks=list(self.tasks)
        for stream in list(self.streams.values()):
            stream.closed=True
            if stream.writer:stream.writer.close()
        for task in tasks:task.cancel()
        try:
            with contextlib.suppress(OSError,ClientError,asyncio.TimeoutError):
                await asyncio.wait_for(self.ws.close(),self.node.connect_timeout)
        finally:
            await asyncio.gather(*tasks,return_exceptions=True)
            self.streams.clear()


class MuxNode:
    def __init__(self,config):
        self.config=config;self.role=config['role']
        if self.role not in ('iran','foreign'):raise ValueError('invalid mux role')
        self.targets=config.get('targets',{});self.listeners=config.get('listeners',{})
        for addresses in [self.targets,self.listeners]:
            for name,address in addresses.items():
                if not NAME.fullmatch(name) or not ipaddress.ip_address(endpoint(address)[0]).is_loopback:raise ValueError('mux services require named literal loopback endpoints')
        self.connect_timeout=5;self.idle_timeout=300
        self.stats=RuntimeStats(config.get('stats_file'));self.sessions=set();self.servers=[];self.runner=None
        self.pool=[None,None];self.pool_locks=[asyncio.Lock(),asyncio.Lock()];self.retry_at=[0,0]
        self.http=None;self.tasks=set();self.stopping=False;self.pending_sessions=0;self.last_error=''

    async def server_link(self,request):
        if len(self.sessions)+self.pending_sessions>=8 or self.stopping:raise web.HTTPServiceUnavailable()
        self.pending_sessions+=1
        ws=web.WebSocketResponse(protocols=[PROTOCOL],compress=False,heartbeat=20,max_msg_size=CHUNK+HEADER.size+1)
        try:
            await ws.prepare(request)
            if ws.ws_protocol!=PROTOCOL:
                await ws.close();return ws
            first=await asyncio.wait_for(ws.receive(),self.connect_timeout)
            if first.type!=WSMsgType.BINARY or unpack(first.data)!=(HELLO,0,GREETING):raise ValueError('missing mux greeting')
            await ws.send_bytes(packet(HELLO,0,GREETING))
            session=Session(self,ws);self.sessions.add(session);self.pending_sessions-=1
            try:await session.receive()
            finally:self.sessions.discard(session)
        except (OSError,ClientError,ValueError,UnicodeError,asyncio.TimeoutError):await ws.close()
        finally:
            if 'session' not in locals():self.pending_sessions-=1
        return ws

    async def lane(self,index):
        async with self.pool_locks[index]:
            session=self.pool[index]
            if session and not session.closed:return session
            if time.monotonic()<self.retry_at[index]:raise ConnectionError('mux reconnect cooldown')
            self.retry_at[index]=time.monotonic()+1
            ws=None
            try:
                ws=await self.http.ws_connect(self.config['url'],ssl=tls_context(self.config),protocols=[PROTOCOL],compress=0,heartbeat=20,max_msg_size=CHUNK+HEADER.size+1)
                if ws.protocol!=PROTOCOL:raise ValueError('mux subprotocol rejected')
                await ws.send_bytes(packet(HELLO,0,GREETING))
                first=await asyncio.wait_for(ws.receive(),self.connect_timeout)
                if first.type!=WSMsgType.BINARY or unpack(first.data)!=(HELLO,0,GREETING):raise ValueError('mux greeting rejected')
                session=Session(self,ws);self.pool[index]=session;self.sessions.add(session)
                async def receive():
                    try:await session.receive()
                    finally:self.sessions.discard(session)
                task=asyncio.create_task(receive());self.tasks.add(task);task.add_done_callback(self.tasks.discard)
                return session
            except BaseException:
                if ws:await ws.close()
                raise

    async def client_stream(self,reader,writer,service):
        task=asyncio.current_task();self.tasks.add(task);stream_task=None
        try:
            if self.stopping or len(self.tasks)>128:return
            order=sorted(range(2),key=lambda i:len(self.pool[i].streams) if self.pool[i] and not self.pool[i].closed else 0)
            for index in order:
                try:
                    session=await self.lane(index);stream_task=await session.open(service,reader,writer);break
                except (OSError,ClientError,ValueError,asyncio.TimeoutError):continue
            if stream_task:await stream_task
        except (OSError,ClientError,ValueError,asyncio.TimeoutError):pass
        finally:
            try:await close_writer(writer)
            finally:self.tasks.discard(task)

    async def start(self):
        try:
            if self.role=='foreign':
                app=web.Application();app.router.add_get('/link',self.server_link)
                self.runner=web.AppRunner(app);await self.runner.setup()
                host,port=endpoint(self.config['listen']);await web.TCPSite(self.runner,host,port,ssl_context=tls_context(self.config,True)).start()
            else:
                from urllib.parse import urlsplit
                url=urlsplit(self.config['url'])
                if url.scheme!='wss' or not url.hostname or url.path!='/link' or url.query or url.fragment or url.username:raise ValueError('mux requires a direct wss /link URL')
                self.http=ClientSession(timeout=ClientTimeout(total=10),trust_env=False)
                for service,address in self.listeners.items():
                    self.servers.append(await asyncio.start_server(lambda r,w,s=service:self.client_stream(r,w,s),*endpoint(address)))
            await self.stats.start()
        except BaseException:
            await self.stop();raise

    async def stop(self):
        self.stopping=True
        for server in self.servers:server.close()
        await asyncio.gather(*(s.wait_closed() for s in self.servers))
        await asyncio.gather(*(s.close() for s in list(self.sessions)),return_exceptions=True)
        tasks=list(self.tasks)
        for task in tasks:task.cancel()
        await asyncio.gather(*tasks,return_exceptions=True)
        if self.http:await self.http.close()
        if self.runner:await self.runner.cleanup()
        self.servers.clear();await self.stats.stop()


async def run(config):
    node=MuxNode(config);done=asyncio.Event()
    for sig in [signal.SIGTERM,signal.SIGINT]:asyncio.get_running_loop().add_signal_handler(sig,done.set)
    try:await node.start();await done.wait()
    finally:await node.stop()


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--config',required=True)
    args=parser.parse_args();asyncio.run(run(json.loads(Path(args.config).read_text())))
