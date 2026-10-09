import asyncio
import unittest
from donino_link.browser import BrowserClient, Credits, WINDOW

class BrowserTests(unittest.IsolatedAsyncioTestCase):
    async def test_credit_bounds_and_invalid_ack(self):
        credit=Credits()
        with self.assertRaises(ValueError):credit.acknowledge()
        for _ in range(WINDOW):await credit.take()
        waiter=asyncio.create_task(credit.take())
        await asyncio.sleep(.01)
        self.assertFalse(waiter.done())
        credit.acknowledge();await asyncio.wait_for(waiter,1)
        self.assertEqual(credit.pending,WINDOW)
        for _ in range(WINDOW):credit.acknowledge()
        with self.assertRaises(ValueError):credit.acknowledge()

    async def test_client_rejects_public_listener_and_plaintext(self):
        for cfg in [{'origin':'http://example.org','listeners':{}},{'origin':'https://example.org','listeners':{'web':'0.0.0.0:30001'}}]:
            client=BrowserClient(cfg)
            with self.assertRaises(ValueError):await client.start()
            await client.stop()

class BrowserServerTests(unittest.IsolatedAsyncioTestCase):
    async def test_binary_frame_boundary_auth_and_half_close(self):
        from aiohttp import WSMsgType
        from aiohttp.test_utils import TestClient,TestServer
        from donino_link.browser import BrowserServer,CHUNK
        import hashlib,os
        async def after_eof(reader,writer):
            data=await reader.read()
            writer.write(hashlib.sha256(data).digest());await writer.drain()
            writer.close();await writer.wait_closed()
        origin=await asyncio.start_server(after_eof,'127.0.0.1',0)
        address='127.0.0.1:'+str(origin.sockets[0].getsockname()[1])
        config={'origin':'https://owned.example','token':'x'*64,'targets':{'echo':address}}
        node=BrowserServer(config)
        client=TestClient(TestServer(node.app));await client.start_server()
        try:
            response=await client.get('/api/stream/echo',headers={'Origin':config['origin']})
            self.assertEqual(response.status,404)
            headers={'Origin':config['origin'],'Cookie':'donino_session='+config['token']}
            ws=await client.ws_connect('/api/stream/echo',headers=headers)
            self.assertEqual((await ws.receive()).data,'ready')
            payload=os.urandom(CHUNK)
            await ws.send_bytes(b'\x00'+payload)
            ack=await asyncio.wait_for(ws.receive(),2)
            self.assertEqual(ack.type,WSMsgType.BINARY)
            self.assertEqual(ack.data,b'\x03')
            await ws.send_bytes(b'\x01')
            data=await asyncio.wait_for(ws.receive(),2)
            self.assertEqual(data.data,b'\x00'+hashlib.sha256(payload).digest())
            await ws.send_bytes(b'\x02')
            self.assertEqual((await asyncio.wait_for(ws.receive(),2)).data,b'\x01')
            await ws.close()
        finally:
            await client.close();origin.close();await origin.wait_closed()
