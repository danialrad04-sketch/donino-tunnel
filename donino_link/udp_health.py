"""Small authenticated UDP round trips, independent of TCP/origin health."""
import asyncio
import hmac
import json
import secrets
import time
from .config import endpoint
from .health import mac


class Responder(asyncio.DatagramProtocol):
    def __init__(self,key): self.key=key
    def connection_made(self,transport): self.transport=transport
    def datagram_received(self,data,addr):
        if len(data)>512:return
        try:
            v=json.loads(data);nonce=v['nonce']
            if not isinstance(nonce,str) or len(nonce)!=64 or not hmac.compare_digest(mac(self.key,'udp-probe:'+nonce),v['auth']):return
            raw=json.dumps({'nonce':nonce,'auth':mac(self.key,'udp-reply:'+nonce)}).encode()
            self.transport.sendto(raw,addr)
        except (ValueError,KeyError,TypeError):return


async def start(listen,key):
    return (await asyncio.get_running_loop().create_datagram_endpoint(lambda:Responder(key),local_addr=endpoint(listen)))[0]


async def probe(address,key,timeout=3):
    loop=asyncio.get_running_loop();future=loop.create_future();nonce=secrets.token_hex(32)
    class Client(asyncio.DatagramProtocol):
        def datagram_received(self,data,addr):
            if len(data)>512 or future.done():return
            try:
                v=json.loads(data)
                if v['nonce']==nonce and hmac.compare_digest(mac(key,'udp-reply:'+nonce),v['auth']):future.set_result(True)
            except (ValueError,KeyError,TypeError):pass
        def error_received(self,error):
            if not future.done():future.set_exception(error)
    transport,_=await loop.create_datagram_endpoint(Client,remote_addr=endpoint(address));started=time.monotonic()
    try:
        transport.sendto(json.dumps({'nonce':nonce,'auth':mac(key,'udp-probe:'+nonce)}).encode())
        await asyncio.wait_for(future,timeout)
        return round((time.monotonic()-started)*1000,3)
    finally:transport.close()
