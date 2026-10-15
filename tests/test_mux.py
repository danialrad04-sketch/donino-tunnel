import asyncio
import contextlib
import os
import socket
import struct
import tempfile
import unittest
from pathlib import Path
from aiohttp import ClientSession,ClientTimeout,WSMsgType,ClientError
from donino_link.mux import MuxNode,Session,Stream,packet,unpack,tls_context,HELLO,OPEN,READY,DATA,UPDATE,FIN,RESET,GREETING,PROTOCOL,HEADER,CREDIT,CHUNK,WINDOW,SLOTS
from donino_link.plan import make_certs
from donino_link.mux import close_writer


def ports():
    # Keep all three reservations open until allocation is complete; closing
    # each immediately lets the kernel return the same port a second time.
    with contextlib.ExitStack() as stack:
        sockets=[stack.enter_context(socket.socket()) for _ in range(3)]
        for sock in sockets:sock.bind(('127.0.0.1',0))
        return [sock.getsockname()[1] for sock in sockets]


class MuxFrameTests(unittest.TestCase):
    def test_version_and_exact_frame_boundaries(self):
        self.assertEqual(unpack(packet(HELLO,0,GREETING)),(HELLO,0,GREETING))
        self.assertEqual(unpack(packet(DATA,1,b'abc')),(DATA,1,b'abc'))
        for raw in [b'',packet(HELLO,0,b'old'),packet(DATA,1,b''),packet(DATA,2,b'a'),packet(FIN,1,b'a'),packet(UPDATE,1,CREDIT.pack(0,1)),packet(DATA,1,b'a')+b'trailing',packet(DATA,1,b'a'*(CHUNK+1)),HEADER.pack(99,1,0)]:
            with self.assertRaises(ValueError):unpack(raw)

    def test_open_is_named_service_not_host_or_shell(self):
        for name in [b'127.0.0.1:22',b'$(whoami)',b'../etc',b'a'*33,b'\xff']:
            with self.assertRaises(ValueError):unpack(packet(OPEN,1,name))
        self.assertEqual(unpack(packet(OPEN,1,b'health'))[2],b'health')


class MuxLiveTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.ca=Path(cls.tmp.name)/'ca'
        make_certs(cls.ca,'127.0.0.1',foreign='127.0.0.1',mux=True)

    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()

    async def asyncSetUp(self):
        self.origins=[];self.origin_tasks=set();self.received=[]
        async def echo(reader,writer):
            task=asyncio.current_task();self.origin_tasks.add(task)
            try:
                data=await reader.read();self.received.append(data)
                writer.write(data[::-1]);await writer.drain()
            finally:
                writer.close();self.origin_tasks.discard(task)
        origin=await asyncio.start_server(echo,'127.0.0.1',0);self.origins.append(origin)
        target='127.0.0.1:'+str(origin.sockets[0].getsockname()[1]);self.public,self.local,self.health=ports()
        common={'ca':str(self.ca/'ca.crt')}
        self.foreign=MuxNode({**common,'role':'foreign','listen':f'127.0.0.1:{self.public}','cert':str(self.ca/'browser.crt'),'key':str(self.ca/'browser.key'),'targets':{'app':target,'health':target}})
        self.iran=MuxNode({**common,'role':'iran','url':f'wss://127.0.0.1:{self.public}/link','cert':str(self.ca/'mux-client.crt'),'key':str(self.ca/'mux-client.key'),'listeners':{'app':f'127.0.0.1:{self.local}','health':f'127.0.0.1:{self.health}'}})
        await self.foreign.start();await self.iran.start()

    async def asyncTearDown(self):
        await asyncio.wait_for(asyncio.gather(self.iran.stop(),self.foreign.stop()),20)
        for server in self.origins:server.close()
        await asyncio.gather(*(s.wait_closed() for s in self.origins))
        for task in self.origin_tasks:task.cancel()
        await asyncio.gather(*self.origin_tasks,return_exceptions=True)

    async def payload(self,data,listen=None):
        reader,writer=await asyncio.open_connection('127.0.0.1',listen or self.local)
        try:
            writer.write(data);await writer.drain();writer.write_eof()
            return await asyncio.wait_for(reader.read(),15)
        finally:await close_writer(writer)

    async def test_concurrent_multimegabyte_payloads_halfclose_and_session_reuse(self):
        payloads=[os.urandom(1024*1024) for _ in range(8)]
        results=await asyncio.gather(*(self.payload(data) for data in payloads))
        self.assertEqual(results,[data[::-1] for data in payloads]);self.assertEqual(len(self.received),8)
        self.assertLessEqual(len(self.iran.sessions),2);self.assertLessEqual(len(self.foreign.sessions),2)
        self.assertEqual(self.iran.stats.bytes_up,8*1024*1024)
        self.assertEqual(self.foreign.stats.bytes_down,8*1024*1024)
        sessions=set(self.iran.sessions)
        self.assertEqual(await self.payload(b'reuse'),b'esuer');self.assertEqual(sessions,self.iran.sessions)

    async def test_health_does_not_inflate_application_counters(self):
        self.assertEqual(await self.payload(b'probe',self.health),b'eborp')
        self.assertEqual(self.iran.stats.bytes_up,0);self.assertEqual(self.foreign.stats.accepted,0)

    async def test_mutual_tls_is_required_before_websocket(self):
        import ssl
        ctx=ssl.create_default_context(cafile=str(self.ca/'ca.crt'));ctx.minimum_version=ssl.TLSVersion.TLSv1_3
        async with ClientSession(timeout=ClientTimeout(total=5)) as client:
            with self.assertRaises((ClientError,OSError,asyncio.TimeoutError)):
                await client.ws_connect(self.iran.config['url'],ssl=ctx,protocols=[PROTOCOL])
        self.assertFalse(self.foreign.sessions)

    async def test_wrong_server_identity_is_rejected(self):
        original=self.iran.config['url'];self.iran.config['url']=original.replace('127.0.0.1','localhost')
        self.assertEqual(await self.payload(b'not delivered'),b'')
        self.assertEqual(self.received,[])

    async def raw(self):
        self.http=ClientSession(timeout=ClientTimeout(total=5));ws=await self.http.ws_connect(self.iran.config['url'],ssl=tls_context(self.iran.config),protocols=[PROTOCOL])
        await ws.send_bytes(packet(HELLO,0,GREETING));first=await ws.receive();self.assertEqual(unpack(first.data),(HELLO,0,GREETING))
        return ws

    async def test_unknown_target_is_reset_without_opening_origin(self):
        ws=await self.raw()
        try:
            await ws.send_bytes(packet(OPEN,1,b'unknown'))
            reply=await asyncio.wait_for(ws.receive(),2);self.assertEqual(unpack(reply.data),(RESET,1,b''))
            self.assertEqual(self.received,[])
        finally:await ws.close();await self.http.close()

    async def test_credit_overflow_fails_closed(self):
        ws=await self.raw()
        try:
            await ws.send_bytes(packet(OPEN,1,b'app'));self.assertEqual(unpack((await ws.receive()).data),(READY,1,b''))
            await ws.send_bytes(packet(UPDATE,1,CREDIT.pack(1,1)))
            reply=await asyncio.wait_for(ws.receive(),2);self.assertIn(reply.type,(WSMsgType.CLOSE,WSMsgType.CLOSED,WSMsgType.ERROR))
        finally:await ws.close();await self.http.close()

    async def test_reset_cleans_one_stream_and_keeps_the_session(self):
        ws=await self.raw()
        try:
            await ws.send_bytes(packet(OPEN,1,b'app'));await ws.receive()
            await ws.send_bytes(packet(RESET,1));await asyncio.sleep(.05)
            self.assertTrue(self.foreign.sessions);self.assertTrue(all(not s.streams for s in self.foreign.sessions))
            self.assertEqual(self.foreign.stats.active,0)
            await ws.send_bytes(packet(OPEN,3,b'health'));self.assertEqual(unpack((await ws.receive()).data),(READY,3,b''))
        finally:await ws.close();await self.http.close()

    async def test_reset_retires_stream_when_completed_send_consumes_cancellation(self):
        ws=await self.raw();entered=asyncio.Event();consumer=[]
        try:
            await ws.send_bytes(packet(OPEN,1,b'app'));await ws.receive()
            session=next(iter(self.foreign.sessions));original=session.send
            async def race(kind,sid,body=b''):
                await original(kind,sid,body)
                if kind==UPDATE:
                    consumer.append(asyncio.current_task());entered.set()
                    try:await asyncio.Event().wait()
                    except asyncio.CancelledError:pass  # Python 3.10 wait_for completion race.
            session.send=race
            await ws.send_bytes(packet(DATA,1,b'payload'))
            await asyncio.wait_for(entered.wait(),2)
            await ws.send_bytes(packet(RESET,1))
            for _ in range(100):
                if not session.streams:break
                await asyncio.sleep(.01)
            retired=not session.streams
            # Ensure a failing implementation can still be torn down cleanly.
            for task in consumer:
                if not task.done():task.cancel()
            await asyncio.gather(*consumer,return_exceptions=True)
            self.assertTrue(retired,'RESET left a consumer waiting after cancellation was consumed')
            self.assertEqual(self.foreign.stats.active,0)
        finally:await ws.close();await self.http.close()

    async def test_stream_ids_cannot_be_reused(self):
        ws=await self.raw()
        try:
            await ws.send_bytes(packet(OPEN,1,b'app'));await ws.receive()
            await ws.send_bytes(packet(OPEN,1,b'app'))
            reply=await asyncio.wait_for(ws.receive(),2)
            self.assertIn(reply.type,(WSMsgType.CLOSE,WSMsgType.CLOSED,WSMsgType.ERROR))
        finally:await ws.close();await self.http.close()

    async def test_duplicate_fin_fails_closed(self):
        ws=await self.raw()
        try:
            await ws.send_bytes(packet(OPEN,1,b'app'));await ws.receive()
            # One WebSocket frame per protocol frame, sent before origin EOF
            # can be processed and retired, to test stream state validation.
            await ws.send_bytes(packet(FIN,1));await ws.send_bytes(packet(FIN,1))
            for _ in range(5):
                reply=await asyncio.wait_for(ws.receive(),2)
                if reply.type in (WSMsgType.CLOSE,WSMsgType.CLOSED,WSMsgType.ERROR):break
            self.assertIn(reply.type,(WSMsgType.CLOSE,WSMsgType.CLOSED,WSMsgType.ERROR))
        finally:await ws.close();await self.http.close()

    async def test_application_capacity_preserves_one_health_stream(self):
        ws=await self.raw()
        try:
            for sid in range(1,62,2):
                await ws.send_bytes(packet(OPEN,sid,b'app'))
                self.assertEqual(unpack((await ws.receive()).data),(READY,sid,b''))
            await ws.send_bytes(packet(OPEN,63,b'app'))
            self.assertEqual(unpack((await ws.receive()).data),(RESET,63,b''))
            await ws.send_bytes(packet(OPEN,65,b'health'))
            self.assertEqual(unpack((await ws.receive()).data),(READY,65,b''))
            self.assertEqual(sum(len(s.streams) for s in self.foreign.sessions),32)
        finally:await ws.close();await self.http.close()

    async def test_session_loss_aborts_without_replay_and_new_flow_reconnects(self):
        reader,writer=await asyncio.open_connection('127.0.0.1',self.local)
        writer.write(b'one attempt');await writer.drain()
        for _ in range(50):
            if self.foreign.stats.bytes_up>=len(b'one attempt'):break
            await asyncio.sleep(.01)
        sessions=list(self.foreign.sessions);self.assertTrue(sessions)
        await asyncio.gather(*(s.close() for s in sessions))
        self.assertEqual(await asyncio.wait_for(reader.read(),2),b'')
        await close_writer(writer);await asyncio.sleep(1.1)
        self.assertEqual(self.iran.stats.active,0);self.assertEqual(self.foreign.stats.active,0)
        self.assertEqual(await self.payload(b'new flow'),b'wolf wen')
        self.assertEqual(self.received.count(b'one attempt'),1)

    async def test_slow_stream_credit_is_bounded_while_another_stream_progresses(self):
        gate=asyncio.Event()
        async def slow(reader,writer):
            task=asyncio.current_task();self.origin_tasks.add(task)
            try:await gate.wait();await reader.read()
            finally:writer.close();self.origin_tasks.discard(task)
        origin=await asyncio.start_server(slow,'127.0.0.1',0);self.origins.append(origin)
        self.foreign.targets['slow']='127.0.0.1:'+str(origin.sockets[0].getsockname()[1])
        for sock in origin.sockets:sock.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,1024)
        session=await self.iran.lane(0)
        accepted=[]
        async def accept(reader,writer):accepted.append(await session.open('slow',reader,writer))
        local=await asyncio.start_server(accept,'127.0.0.1',0);self.origins.append(local)
        reader,writer=await asyncio.open_connection('127.0.0.1',local.sockets[0].getsockname()[1])
        producer=asyncio.create_task(self.fill(writer))
        try:
            for _ in range(100):
                streams=[p for s in self.foreign.sessions for p in s.streams.values() if p.service=='slow']
                if streams and streams[0].rx_slots==0:break
                await asyncio.sleep(.02)
            self.assertTrue(streams);self.assertEqual(streams[0].rx_slots,0);self.assertLessEqual(streams[0].incoming.qsize(),SLOTS+1)
            self.assertLessEqual(WINDOW-streams[0].rx_credit,WINDOW)
            async def fast_accept(reader,writer):await session.open('app',reader,writer)
            fast=await asyncio.start_server(fast_accept,'127.0.0.1',0);self.origins.append(fast)
            self.assertEqual(await asyncio.wait_for(self.payload(b'fast',fast.sockets[0].getsockname()[1]),2),b'tsaf')
        finally:
            gate.set();producer.cancel();await asyncio.gather(producer,return_exceptions=True)
            await close_writer(writer)

    async def fill(self,writer):
        for _ in range(1024):writer.write(b'x'*CHUNK);await writer.drain()
