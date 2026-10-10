import asyncio
import contextlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from aiohttp import ClientSession, ClientTimeout, WSMsgType, ClientError
from donino_link.continuum import (ContinuumNode, DurableSession, Flow, ProtocolError,
    packet, unpack, hello, snapshot, PROTOCOL, OPEN, READY, DATA, ACK, FIN, FIN_ACK,
    CHUNK, WINDOW, SLOTS)
from donino_link.mux import tls_context, close_writer
from donino_link.plan import make_certs
from test_mux import ports


class ContractTests(unittest.TestCase):
    def test_exact_frame_ranges_and_named_targets(self):
        self.assertEqual(unpack(packet(DATA,1,7,b'abc')),(DATA,1,7,b'abc'))
        for raw in [b'',packet(DATA,2,0,b'a'),packet(DATA,1),packet(DATA,1,0,b'x'*(CHUNK+1)),packet(OPEN,1,0,b'127.0.0.1:22'),packet(READY,1,1),packet(ACK,1,0,b'x'),packet(DATA,1,(1<<64)-1,b'x')]:
            with self.assertRaises(ProtocolError):unpack(raw)

    def test_snapshot_bounds_and_strict_types(self):
        self.assertEqual(snapshot({'1':[0,False,True,False]}),{1:[0,False,True,False]})
        for value in [[],{'01':[0,False,True,False]},{'2':[0,False,True,False]},{'1':[True,False,True,False]},{'1':[0,0,True,False]},{'1':[-1,False,True,False]},{str(i*2+1):[0,False,False,False] for i in range(161)}]:
            with self.assertRaises(ProtocolError):snapshot(value)

    def test_greeting_rejects_missing_fields_and_credentials(self):
        value={'version':PROTOCOL,'id':'a'*32,'token':'b'*64,'epoch':1,'resume':False,'streams':{}}
        self.assertEqual(hello(json.dumps(value))['epoch'],1)
        for field,bad in [('epoch',True),('token','g'*64),('resume',0),('streams',[]),('version','donino-mux.v1')]:
            with self.assertRaises(ProtocolError):hello(json.dumps({**value,field:bad}))


class StateTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        class Node:role='iran'
        self.session=DurableSession(Node());self.flow=Flow(self.session,1,'app')

    async def test_ack_cannot_skip_unsent_or_split_frame(self):
        self.flow.pending.extend([(0,b'abc'),(3,b'def')]);self.flow.tx_end=6
        for offset in [2,7]:
            with self.assertRaises(ProtocolError):await self.flow.acknowledge(offset)
        await self.flow.acknowledge(3);self.assertEqual(list(self.flow.pending),[(3,b'def')])
        await self.flow.acknowledge(0);self.assertEqual(self.flow.tx_ack,3)
        with self.assertRaises(ProtocolError):await self.flow.acknowledge(6,True)
        self.flow.local_fin=True;await self.flow.acknowledge(6,True);self.assertTrue(self.flow.fin_acked)

    async def test_replay_deduplicates_queued_bytes_but_rejects_overlap(self):
        self.flow.receive_data(0,b'abc');self.flow.receive_data(0,b'abc');self.assertEqual(self.flow.incoming.qsize(),1)
        for offset,body in [(2,b'cd'),(4,b'd')]:
            with self.assertRaises(ProtocolError):self.flow.receive_data(offset,body)
        self.flow.receive_fin(3);self.flow.receive_fin(3);self.assertEqual(self.flow.incoming.qsize(),2)
        with self.assertRaises(ProtocolError):self.flow.receive_data(3,b'd')

    async def test_receive_window_limits_tiny_frames_and_bytes(self):
        for index in range(SLOTS):self.flow.receive_data(index,b'x')
        with self.assertRaises(ProtocolError):self.flow.receive_data(SLOTS,b'x')
        other=Flow(self.session,3,'app')
        for index in range(SLOTS):other.receive_data(index*CHUNK,b'x'*CHUNK)
        self.assertEqual(other.rx_next,WINDOW)
        with self.assertRaises(ProtocolError):other.receive_data(WINDOW,b'x')


class LiveTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.ca=Path(cls.tmp.name)/'ca'
        make_certs(cls.ca,'127.0.0.1',foreign='127.0.0.1',mux=True)
    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()

    async def asyncSetUp(self):
        self.origin_tasks=set();self.received=[];self.origin_connections=0
        async def echo(reader,writer):
            task=asyncio.current_task();self.origin_tasks.add(task);self.origin_connections+=1;blocks=[]
            try:
                while block:=await reader.read(8192):
                    blocks.append(block);writer.write(block);await writer.drain()
                self.received.append(b''.join(blocks));writer.write_eof();await writer.drain()
            finally:writer.close();self.origin_tasks.discard(task)
        self.origin=await asyncio.start_server(echo,'127.0.0.1',0)
        target='127.0.0.1:'+str(self.origin.sockets[0].getsockname()[1]);self.public,self.local,self.health=ports()
        common={'ca':str(self.ca/'ca.crt'),'recovery_timeout':2}
        self.foreign=ContinuumNode({**common,'role':'foreign','listen':f'127.0.0.1:{self.public}','cert':str(self.ca/'browser.crt'),'key':str(self.ca/'browser.key'),'targets':{'app':target,'health':target}})
        self.iran=ContinuumNode({**common,'role':'iran','url':f'wss://127.0.0.1:{self.public}/continuum','cert':str(self.ca/'mux-client.crt'),'key':str(self.ca/'mux-client.key'),'listeners':{'app':f'127.0.0.1:{self.local}','health':f'127.0.0.1:{self.health}'}})
        await self.foreign.start();await self.iran.start()

    async def asyncTearDown(self):
        await asyncio.wait_for(asyncio.gather(self.iran.stop(),self.foreign.stop()),15)
        self.origin.close();await self.origin.wait_closed();tasks=list(self.origin_tasks)
        for task in tasks:task.cancel()
        await asyncio.gather(*tasks,return_exceptions=True)

    async def wait(self,predicate,timeout=5):
        async def check():
            while not predicate():await asyncio.sleep(.01)
        await asyncio.wait_for(check(),timeout)

    async def payload(self,data,port=None):
        reader,writer=await asyncio.open_connection('127.0.0.1',port or self.local)
        async def write():writer.write(data);await writer.drain();writer.write_eof()
        task=asyncio.create_task(write())
        try:
            result=await asyncio.wait_for(reader.read(),10);await task;return result
        finally:
            task.cancel();await asyncio.gather(task,return_exceptions=True);await close_writer(writer)

    async def abort_lanes(self):
        for session in list(self.foreign.sessions):
            if session.ws:session.ws._req.transport.abort()

    async def test_eight_concurrent_megabyte_transfers_halfclose_and_unique_counters(self):
        blocks=[os.urandom(1024*1024) for _ in range(8)]
        self.assertEqual(await asyncio.gather(*(self.payload(b) for b in blocks)),blocks)
        self.assertEqual(self.origin_connections,8)
        await self.wait(lambda:self.iran.stats.active==0 and self.foreign.stats.active==0)
        self.assertEqual(self.iran.stats.bytes_up,8*1024*1024);self.assertEqual(self.foreign.stats.bytes_up,8*1024*1024)
        self.assertLessEqual(len(self.iran.sessions),2)

    async def test_live_upload_and_download_survive_three_lane_losses(self):
        reader,writer=await asyncio.open_connection('127.0.0.1',self.local);blocks=[os.urandom(128*1024) for _ in range(4)]
        try:
            for index,block in enumerate(blocks):
                writer.write(block);await writer.drain();self.assertEqual(await asyncio.wait_for(reader.readexactly(len(block)),5),block)
                if index<3:
                    before=self.iran.recoveries;await self.abort_lanes();await self.wait(lambda:self.iran.recoveries>before)
                    self.assertEqual(self.origin_connections,1)
            writer.write_eof();self.assertEqual(await asyncio.wait_for(reader.read(),5),b'')
            await self.wait(lambda:len(self.received)==1);self.assertEqual(self.received,[b''.join(blocks)])
            self.assertEqual(self.iran.stats.bytes_up,sum(map(len,blocks)));self.assertEqual(self.foreign.stats.bytes_up,sum(map(len,blocks)))
        finally:await close_writer(writer)

    async def loss(self,kind,data):
        original=DurableSession.send;dropped=asyncio.Event()
        async def send(session,k,sid,offset=0,body=b''):
            if session.node is self.foreign and k==kind and not dropped.is_set():
                dropped.set();session.ws._req.transport.abort();return
            await original(session,k,sid,offset,body)
        DurableSession.send=send
        try:
            self.assertEqual(await self.payload(data),data);self.assertTrue(dropped.is_set())
            self.assertEqual(self.received,[data]);self.assertEqual(self.origin_connections,1)
            self.assertEqual(self.foreign.stats.bytes_up,len(data))
            await self.wait(lambda:self.iran.stats.active==0 and self.foreign.stats.active==0)
        finally:DurableSession.send=original

    async def test_lost_data_ack_replays_without_duplicate_origin_write(self):await self.loss(ACK,os.urandom(512*1024))
    async def test_lost_fin_ack_preserves_halfclose_and_recovery(self):await self.loss(FIN_ACK,os.urandom(65536))
    async def test_recovery_after_open_before_ready_does_not_reopen_origin(self):await self.loss(READY,b'pending acceptance')

    async def test_eight_inflight_transfers_recover_together(self):
        blocks=[os.urandom(2*1024*1024) for _ in range(8)]
        transfer=asyncio.ensure_future(asyncio.gather(*(self.payload(b) for b in blocks)))
        try:
            await self.wait(lambda:self.foreign.stats.active==8 and self.foreign.stats.bytes_up>0)
            await self.abort_lanes()
            self.assertEqual(await transfer,blocks)
            self.assertEqual(self.origin_connections,8)
            self.assertEqual(sorted(self.received),sorted(blocks))
            self.assertGreaterEqual(self.iran.recoveries,1)
        finally:
            transfer.cancel();await asyncio.gather(transfer,return_exceptions=True)

    async def test_window_full_both_directions_resumes_and_drains(self):
        original=DurableSession.send;hold=True
        async def send(session,kind,sid,offset=0,body=b''):
            if kind==ACK and hold:return
            await original(session,kind,sid,offset,body)
        DurableSession.send=send
        transfer=asyncio.create_task(self.payload(os.urandom(2*1024*1024)))
        try:
            await self.wait(lambda:any(len(f.pending)==SLOTS for sess in self.iran.sessions for f in sess.streams.values()) and any(len(f.pending)==SLOTS for sess in self.foreign.sessions for f in sess.streams.values()))
            hold=False;await self.abort_lanes()
            result=await transfer
            self.assertEqual(self.received,[result]);self.assertEqual(self.origin_connections,1)
            self.assertGreaterEqual(self.iran.recoveries,1)
        finally:
            hold=False;DurableSession.send=original
            transfer.cancel();await asyncio.gather(transfer,return_exceptions=True)

    async def test_unsent_data_is_replayed_after_socket_abort(self):
        original=DurableSession.send;dropped=asyncio.Event()
        async def send(session,kind,sid,offset=0,body=b''):
            if session.node is self.iran and kind==DATA and not dropped.is_set():
                dropped.set()
                # Drop before DATA reaches the foreign peer; pending holds it.
                session.ws._response.connection.transport.abort()
                return
            await original(session,kind,sid,offset,body)
        DurableSession.send=send
        try:
            data=os.urandom(512*1024)
            self.assertEqual(await self.payload(data),data)
            self.assertEqual(self.received,[data]);self.assertEqual(self.origin_connections,1)
            self.assertTrue(dropped.is_set());self.assertGreater(self.iran.replayed_bytes,0)
            self.assertEqual(self.foreign.stats.bytes_up,len(data))
        finally:DurableSession.send=original

    async def test_binding_lock_rechecks_epoch_after_a_competing_handshake(self):
        session=await self.iran.lane(0);foreign=next(iter(self.foreign.sessions))
        await foreign.bind_lock.acquire()
        client=None;ws=None
        try:
            _,client,ws=await self.raw(epoch=2)
            # Keep the request waiting at the bind lock, then simulate a newer
            # admitted generation. The stale waiter must not replace the lane.
            await asyncio.sleep(.05);foreign.epoch=3;old=foreign.ws
            foreign.bind_lock.release()
            reply=await asyncio.wait_for(ws.receive(),2)
            self.assertEqual(reply.type,WSMsgType.CLOSE);self.assertEqual(reply.data,1008)
            self.assertIs(foreign.ws,old);self.assertFalse(session.closed)
        finally:
            if foreign.bind_lock.locked():foreign.bind_lock.release()
            if ws:await ws.close()
            if client:await client.close()

    async def test_foreign_restart_closes_old_flow_without_recreating_origin(self):
        reader,writer=await asyncio.open_connection('127.0.0.1',self.local)
        try:
            writer.write(b'once');await writer.drain();self.assertEqual(await asyncio.wait_for(reader.readexactly(4),5),b'once')
            config=self.foreign.config;await self.foreign.stop();self.foreign=ContinuumNode(config);await self.foreign.start()
            self.assertEqual(await asyncio.wait_for(reader.read(),5),b'');self.assertEqual(self.origin_connections,1)
        finally:await close_writer(writer)

    async def test_recovery_deadline_aborts_stalled_flow(self):
        reader,writer=await asyncio.open_connection('127.0.0.1',self.local)
        try:
            writer.write(b'once');await writer.drain();self.assertEqual(await asyncio.wait_for(reader.readexactly(4),5),b'once')
            self.foreign.stopping=True;await self.abort_lanes()
            self.assertEqual(await asyncio.wait_for(reader.read(),5),b'');self.assertEqual(self.origin_connections,1)
            self.assertGreaterEqual(self.iran.expired,1)
        finally:await close_writer(writer)

    async def test_health_does_not_inflate_application_counters(self):
        self.assertEqual(await self.payload(b'probe',self.health),b'probe')
        self.assertEqual(self.iran.stats.bytes_up,0);self.assertEqual(self.foreign.stats.accepted,0)

    async def raw(self,token=None,epoch=None,client_cert='mux-client'):
        session=await self.iran.lane(0);client=ClientSession(timeout=ClientTimeout(total=5))
        config={**self.iran.config,'cert':str(self.ca/(client_cert+'.crt')),'key':str(self.ca/(client_cert+'.key'))}
        ws=await client.ws_connect(config['url'],ssl=tls_context(config),protocols=[PROTOCOL])
        value={'version':PROTOCOL,'id':session.identity,'token':token or session.token,'epoch':epoch if epoch is not None else session.epoch+1,'resume':True,'streams':session.states()}
        await ws.send_str(json.dumps(value));return session,client,ws

    async def test_bad_token_stale_epoch_and_other_peer_do_not_kill_valid_session(self):
        for args in [{'token':'0'*64},{'epoch':1},{'client_cert':'client'}]:
            session,client,ws=await self.raw(**args)
            try:
                reply=await asyncio.wait_for(ws.receive(),2);self.assertEqual(reply.type,WSMsgType.CLOSE);self.assertEqual(reply.data,1008)
                self.assertFalse(session.closed)
            finally:await ws.close();await client.close()
        self.assertEqual(await self.payload(b'still authorized'),b'still authorized')

    async def test_replaced_lane_cannot_close_new_lane(self):
        session=await self.iran.lane(0);foreign=next(iter(self.foreign.sessions));old=foreign.ws
        await self.abort_lanes();await self.wait(lambda:self.iran.recoveries>=1);replacement=foreign.ws
        self.assertIsNot(replacement,old);foreign.detach(old)
        self.assertIs(foreign.ws,replacement);self.assertTrue(foreign.connected.is_set());self.assertFalse(session.closed)

    async def test_invalid_ack_terminates_instead_of_resuming(self):
        session=await self.iran.lane(0);reader,writer=await asyncio.open_connection('127.0.0.1',self.local)
        try:
            writer.write(b'abc');await writer.drain();self.assertEqual(await asyncio.wait_for(reader.readexactly(3),5),b'abc')
            flow=next(iter(session.streams.values()));await session.ws.send_bytes(packet(ACK,flow.sid,99999))
            self.assertEqual(await asyncio.wait_for(reader.read(),5),b'');self.assertEqual(self.foreign.last_error,'ACK beyond sent data')
        finally:await close_writer(writer)

    async def test_tls_client_certificate_required(self):
        import ssl
        ctx=ssl.create_default_context(cafile=str(self.ca/'ca.crt'))
        async with ClientSession(timeout=ClientTimeout(total=5)) as client:
            with self.assertRaises((ClientError,OSError,asyncio.TimeoutError)):
                await client.ws_connect(self.iran.config['url'],ssl=ctx,protocols=[PROTOCOL])
        self.assertFalse(self.foreign.sessions)
