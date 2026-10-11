import asyncio
import contextlib
import socket
import ssl
import tempfile
import unittest
from pathlib import Path
from donino_link.plan import make_certs
from donino_link.tlsfront import TLSFront


class TLSFrontTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory()
        cls.ca=Path(cls.tmp.name)/'ca'
        make_certs(cls.ca,'127.0.0.1',foreign='127.0.0.1')

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    async def asyncSetUp(self):
        async def echo(reader,writer):
            try:
                while data:=await reader.read(65536):
                    writer.write(data);await writer.drain()
            finally:
                writer.close()
                with contextlib.suppress(OSError):await writer.wait_closed()
        self.upstream=await asyncio.start_server(echo,'127.0.0.1',0)
        upstream_port=self.upstream.sockets[0].getsockname()[1]
        with socket.socket() as reserve:
            reserve.bind(('127.0.0.1',0));port=reserve.getsockname()[1]
        self.front=TLSFront(f'127.0.0.1:{port}',f'127.0.0.1:{upstream_port}',
                            str(self.ca/'server.crt'),str(self.ca/'server.key'),str(self.ca/'ca.crt'))
        await self.front.start()
        self.port=port

    async def asyncTearDown(self):
        await self.front.stop()
        self.upstream.close();await self.upstream.wait_closed()

    async def connect(self,authenticated=True):
        context=ssl.create_default_context(cafile=str(self.ca/'ca.crt'))
        if authenticated:context.load_cert_chain(self.ca/'client.crt',self.ca/'client.key')
        return await asyncio.wait_for(asyncio.open_connection('127.0.0.1',self.port,ssl=context),3)

    async def test_authenticated_tls_round_trip(self):
        reader,writer=await self.connect()
        try:
            payload=b'Ubuntu native Python TLS front\x00'*4096
            writer.write(payload);await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.readexactly(len(payload)),3),payload)
        finally:
            writer.close()
            with contextlib.suppress(OSError):await writer.wait_closed()

    async def test_client_without_certificate_cannot_send_data(self):
        writer=None
        try:
            reader,writer=await self.connect(False)
            writer.write(b'unauthenticated');await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.read(100),3),b'')
        except (ssl.SSLError,ConnectionError):
            pass
        finally:
            if writer:
                writer.close()
                with contextlib.suppress(OSError):await writer.wait_closed()
