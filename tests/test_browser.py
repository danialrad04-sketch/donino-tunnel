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
