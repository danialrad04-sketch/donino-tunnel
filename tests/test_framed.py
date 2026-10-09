import asyncio
import hashlib
import os
import unittest
from donino_link.framed import FramedRelay,frame,HEADER,CHUNK

class FramedTests(unittest.IsolatedAsyncioTestCase):
    async def test_frame_size_validation(self):
        for kind,size in [(0,0),(0,CHUNK+1),(1,1),(2,0)]:
            reader=asyncio.StreamReader();reader.feed_data(HEADER.pack(kind,size))
            with self.assertRaises(ValueError):await frame(reader)

    async def test_response_after_upload_eof_through_both_relays(self):
        tasks=set()
        async def target(r,w):
            task=asyncio.current_task();tasks.add(task)
            try:
                data=await r.read();await asyncio.sleep(.02)
                w.write(hashlib.sha256(data).digest());await w.drain()
            finally:w.close();await w.wait_closed();tasks.discard(task)
        origin=await asyncio.start_server(target,'127.0.0.1',0)
        destination='127.0.0.1:'+str(origin.sockets[0].getsockname()[1])
        outside=FramedRelay({'role':'foreign','listeners':[{'listen':'127.0.0.1:12650','target':destination}]})
        inside=FramedRelay({'role':'iran','listeners':[{'listen':'127.0.0.1:12651','target':'127.0.0.1:12650'}]})
        try:
            await outside.start();await inside.start()
            r,w=await asyncio.open_connection('127.0.0.1',12651)
            payload=os.urandom(2*CHUNK+3)
            w.write(payload);await w.drain();w.write_eof()
            self.assertEqual(await asyncio.wait_for(r.read(),2),hashlib.sha256(payload).digest())
            w.close();await w.wait_closed()
        finally:
            await inside.stop();await outside.stop();origin.close();await origin.wait_closed()
            for task in list(tasks):task.cancel()
            await asyncio.gather(*tasks,return_exceptions=True)

    async def test_public_endpoint_rejected(self):
        relay=FramedRelay({'role':'foreign','listeners':[{'listen':'0.0.0.0:12000','target':'127.0.0.1:443'}]})
        with self.assertRaises(ValueError):await relay.start()
