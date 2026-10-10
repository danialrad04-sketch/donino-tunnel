import asyncio
import copy
import contextlib
import json
import socket
import struct
import unittest
from donino_link.health import responder
from donino_link.udp_health import Responder
from donino_link.import_health import test as imported_test, key_id


class Relay(asyncio.DatagramProtocol):
    def __init__(self,target):self.target=target;self.client=None;self.header=None
    def connection_made(self,transport):self.transport=transport
    def datagram_received(self,data,address):
        if address==self.target and self.client:self.transport.sendto(self.header+data,self.client)
        elif len(data)>10 and data[:4]==b'\x00\x00\x00\x01':
            self.client=address;self.header=data[:10];self.transport.sendto(data[10:],self.target)


class ImportedHealthTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.key='1'*64;self.tasks=set();self.datagrams=[]
        self.origin=await asyncio.start_server(lambda r,w:responder(r,w,self.key),'127.0.0.1',0)
        self.udp=(await asyncio.get_running_loop().create_datagram_endpoint(lambda:Responder(self.key),local_addr=('127.0.0.1',0)))[0]
        self.proxy=await asyncio.start_server(self.handler,'127.0.0.1',0)
        self.cfg={'role':'client','socks5':[{'listen':':'+str(self.proxy.sockets[0].getsockname()[1]),'username':'user','password':'secret'}]}
        self.material={'key':self.key,'tcp':'127.0.0.1:'+str(self.origin.sockets[0].getsockname()[1]),'udp':'127.0.0.1:'+str(self.udp.get_extra_info('sockname')[1])}
    async def asyncTearDown(self):
        for server in (self.proxy,self.origin):server.close();await server.wait_closed()
        self.udp.close()
        for transport in self.datagrams:transport.close()
        for task in list(self.tasks):task.cancel()
        await asyncio.gather(*self.tasks,return_exceptions=True)
    async def handler(self,reader,writer):
        self.tasks.add(asyncio.current_task());remote=None
        try:
            if await reader.readexactly(3)!=b'\x05\x01\x02':return
            writer.write(b'\x05\x02');await writer.drain()
            version,length=await reader.readexactly(2);user=await reader.readexactly(length)
            length=(await reader.readexactly(1))[0];password=await reader.readexactly(length)
            if user!=b'user' or password!=b'secret':writer.write(b'\x01\x01');await writer.drain();return
            writer.write(b'\x01\x00');await writer.drain()
            head=await reader.readexactly(4);target=await reader.readexactly(6)
            host=socket.inet_ntoa(target[:4]);port=struct.unpack('!H',target[4:])[0]
            if head[1]==1:
                origin,remote=await asyncio.open_connection(host,port)
                writer.write(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00');await writer.drain()
                async def pipe(source,sink):
                    while data:=await source.read(8192):sink.write(data);await sink.drain()
                    sink.close()
                await asyncio.gather(pipe(reader,remote),pipe(origin,writer))
            elif head[1]==3:
                target=('127.0.0.1',self.udp.get_extra_info('sockname')[1])
                transport,_=await asyncio.get_running_loop().create_datagram_endpoint(lambda:Relay(target),local_addr=('127.0.0.1',0));self.datagrams.append(transport)
                writer.write(b'\x05\x00\x00\x01\x00\x00\x00\x00'+struct.pack('!H',transport.get_extra_info('sockname')[1]));await writer.drain()
                await reader.read();transport.close()
        except (OSError,asyncio.IncompleteReadError):pass
        finally:
            if remote:remote.close()
            writer.close()
            with contextlib.suppress(OSError):await writer.wait_closed()
            self.tasks.discard(asyncio.current_task())
    async def test_authenticated_socks_tcp_and_udp_real_signed_responders(self):
        original=copy.deepcopy(self.cfg);result=await asyncio.to_thread(imported_test,self.cfg,self.material)
        self.assertTrue(result['tcp_ok'],result);self.assertTrue(result['udp_ok'],result);self.assertEqual(self.cfg,original)
        self.assertGreater(result['tcp_latency_ms'],0);self.assertNotIn('secret',json.dumps(result))
    async def test_wrong_proxy_credentials_are_not_reported_as_healthy(self):
        self.cfg['socks5'][0]['password']='incorrect'
        result=await asyncio.to_thread(imported_test,self.cfg,self.material)
        self.assertFalse(result['tcp_ok']);self.assertFalse(result['udp_ok']);self.assertNotIn('incorrect',json.dumps(result))
    async def test_no_socks_route_is_unverified_and_remote_target_rejected(self):
        result=imported_test({'role':'client'},self.material)
        self.assertIsNone(result['tcp_ok']);self.assertIsNone(result['udp_ok'])
        with self.assertRaises(ValueError):imported_test(self.cfg,{**self.material,'tcp':'198.51.100.1:19090'})
        self.assertIsNone(key_id({}));self.assertEqual(key_id({'transport':{'kcp':{'key':'matching'}}}),key_id({'transport':{'kcp':{'key':'matching'}}}))

if __name__=='__main__':unittest.main()
