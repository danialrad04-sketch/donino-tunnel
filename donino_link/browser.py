"""Experimental BrowserLink: native Chromium WebSockets to an owned HTTPS site.

No custom cryptography or arbitrary destination proxy. Credit-based framing bounds
queued data in both directions. TCP streams cannot survive a browser disconnect.
"""
import argparse
import asyncio
import base64
import contextlib
import json
import os
import secrets
import signal
import ssl
from pathlib import Path
from urllib.parse import urlsplit
from aiohttp import web, WSMsgType
from .config import endpoint

CHUNK = 32768
WINDOW = 16
MAX_STREAMS = 32
DATA, EOF, DOWN_ACK, UP_ACK = range(4)


class Credits:
    def __init__(self):
        self.sem = asyncio.Semaphore(WINDOW)
        self.pending = 0

    async def take(self):
        await self.sem.acquire()
        self.pending += 1

    def acknowledge(self):
        if self.pending <= 0:
            raise ValueError('unexpected credit')
        self.pending -= 1
        self.sem.release()


class BrowserServer:
    def __init__(self, config):
        self.config = config
        self.active = 0
        self.runner = None
        self.app = web.Application(client_max_size=1024)
        self.app.router.add_get('/', self.page)
        self.app.router.add_get('/api/stream/{service}', self.stream)

    async def page(self, request):
        return web.Response(text='''<!doctype html><html lang="fa" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Donino Workspace</title><style>body{font:18px system-ui;background:#111827;color:#e5e7eb;max-width:680px;margin:12vh auto;padding:24px}h1{color:#c4b5fd}p{line-height:1.8}</style><h1>Donino Workspace</h1><p>درگاه خصوصی ارتباط و مدیریت سرویس‌ها</p><p>این صفحه روی دامنهٔ مالک سرویس میزبانی می‌شود.</p></html>''', content_type='text/html', headers={
            'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'",
            'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-store'})

    async def stream(self, request):
        cfg = self.config
        valid = secrets.compare_digest(request.cookies.get('donino_session', ''), cfg['token'])
        target = cfg['targets'].get(request.match_info['service'])
        if not valid or request.headers.get('Origin') != cfg['origin'] or target is None:
            raise web.HTTPNotFound()
        if self.active >= MAX_STREAMS:
            raise web.HTTPServiceUnavailable()
        self.active += 1
        writer = None
        ws = web.WebSocketResponse(max_msg_size=CHUNK+1, compress=False, heartbeat=20, receive_timeout=300)
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(*endpoint(target)), 5)
            await ws.prepare(request)
            await ws.send_str('ready')
            down_credit = Credits()
            up_eof = asyncio.Event()
            down_eof = asyncio.Event()

            async def download():
                while True:
                    await down_credit.take()
                    block = await reader.read(CHUNK)
                    if not block:
                        # Reserved credit did not carry a frame.
                        down_credit.pending -= 1
                        down_credit.sem.release()
                        await ws.send_bytes(bytes([EOF]))
                        down_eof.set()
                        if up_eof.is_set():
                            await ws.close()
                        return
                    await ws.send_bytes(bytes([DATA])+block)

            async def receive():
                async for message in ws:
                    if message.type != WSMsgType.BINARY or not message.data:
                        raise ValueError('invalid frame')
                    kind, payload = message.data[0], message.data[1:]
                    if kind == DATA and payload and not up_eof.is_set():
                        writer.write(payload)
                        await writer.drain()
                        await ws.send_bytes(bytes([UP_ACK]))
                    elif kind == DOWN_ACK and not payload:
                        down_credit.acknowledge()
                    elif kind == EOF and not payload and not up_eof.is_set():
                        writer.write_eof()
                        up_eof.set()
                        if down_eof.is_set():
                            await ws.close()
                    else:
                        raise ValueError('invalid frame state')

            tasks = [asyncio.create_task(download()), asyncio.create_task(receive())]
            try:
                # Receive finishes on disconnect; a normal download EOF leaves
                # upload open. Exceptions must cancel the opposite direction.
                done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    task.result()
                if tasks[1] not in done:
                    await tasks[1]
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
        except (OSError, ValueError, asyncio.TimeoutError):
            if ws.prepared:
                await ws.close(code=1002)
            else:
                raise web.HTTPServiceUnavailable()
        finally:
            if writer:
                writer.close()
                with contextlib.suppress(OSError):
                    await writer.wait_closed()
            self.active -= 1
        return ws

    async def start(self):
        cfg = self.config
        for target in cfg['targets'].values():
            host, _ = endpoint(target)
            import ipaddress
            if not ipaddress.ip_address(host).is_loopback:
                raise ValueError('BrowserLink targets must be literal loopback addresses')
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cfg['cert'], cfg['key'])
        self.runner = web.AppRunner(self.app, access_log=None)
        await self.runner.setup()
        await web.TCPSite(self.runner, *endpoint(cfg['listen']), ssl_context=context).start()

    async def stop(self):
        if self.runner:
            await self.runner.cleanup()


class BrowserClient:
    def __init__(self, config):
        self.config = config
        self.process = None
        self.ready = asyncio.Event()
        self.streams = {}
        self.servers = []
        self.supervisor = None
        self.send_lock = asyncio.Lock()
        self.tasks = set()

    async def send(self, **command):
        async with self.send_lock:
            if not self.process or self.process.returncode is not None:
                raise ConnectionError('browser unavailable')
            self.process.stdin.write(json.dumps(command, separators=(',', ':')).encode()+b'\n')
            await self.process.stdin.drain()

    async def supervise(self):
        delay = 1
        while True:
            try:
                url = urlsplit(self.config['origin'])
                tls = ssl.create_default_context(cafile=self.config.get('ca'))
                # Scoped browser SPKI exception never substitutes for hostname,
                # CA and certificate lifetime verification before startup.
                _, checked = await asyncio.wait_for(asyncio.open_connection(url.hostname, url.port or 443, ssl=tls, server_hostname=url.hostname), 10)
                checked.close()
                with contextlib.suppress(OSError):
                    await checked.wait_closed()
                env = os.environ.copy()
                # Browser traffic must not inherit a controller's HTTP proxy.
                for key in list(env):
                    if key.lower() in ('http_proxy','https_proxy','all_proxy'):
                        env.pop(key)
                self.process = await asyncio.create_subprocess_exec(
                    'node', str(Path(__file__).with_name('resources')/'browser_bridge.js'),
                    stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                    limit=CHUNK*4, env=env)
                await self.send(op='init', config=self.config)
                while line := await self.process.stdout.readline():
                    event = json.loads(line)
                    kind = event['event']
                    if kind == 'ready':
                        self.ready.set()
                        delay = 1
                        continue
                    stream = self.streams.get(event.get('id'))
                    if stream is None:
                        continue
                    if kind == 'ack':
                        stream['credit'].acknowledge()
                    elif kind == 'open':
                        stream['open'].set_result(True) if not stream['open'].done() else None
                    elif kind == 'close':
                        stream['queue'].put_nowait(event)
                    elif kind in ('data', 'eof'):
                        # Browser's download credits prevent more than WINDOW
                        # unacknowledged data events per stream.
                        stream['queue'].put_nowait(event)
                    else:
                        raise ValueError('unknown browser event')
                raise ConnectionError('browser exited')
            except asyncio.CancelledError:
                raise
            except (OSError, ValueError, ConnectionError, asyncio.QueueFull) as error:
                print("BrowserLink restarting: "+type(error).__name__, flush=True)
                self.ready.clear()
                for stream in self.streams.values():
                    stream['closed'].set()
            finally:
                if self.process and self.process.returncode is None:
                    self.process.terminate()
                    try:
                        await asyncio.wait_for(self.process.wait(), 5)
                    except asyncio.TimeoutError:
                        self.process.kill()
                        await self.process.wait()
                self.process = None
                self.ready.clear()
            await asyncio.sleep(delay + secrets.randbelow(500)/1000)
            delay = min(delay*2, 30)

    async def accept(self, service, reader, writer):
        task = asyncio.current_task()
        self.tasks.add(task)
        ident = secrets.token_hex(12)
        stream = None
        transfer = []
        try:
            if not self.ready.is_set() or len(self.streams) >= MAX_STREAMS:
                return
            loop = asyncio.get_running_loop()
            stream = {'credit': Credits(), 'open': loop.create_future(), 'closed': asyncio.Event(),
                      'queue': asyncio.Queue(WINDOW+2)}
            self.streams[ident] = stream
            await self.send(op='open', id=ident, service=service)

            async def upload():
                await asyncio.wait_for(stream['open'], 10)
                while True:
                    await stream['credit'].take()
                    block = await reader.read(CHUNK)
                    if not block:
                        await self.send(op='eof', id=ident)
                        return
                    await self.send(op='data', id=ident, data=base64.b64encode(block).decode())

            async def download():
                while True:
                    event = await stream['queue'].get()
                    if event['event'] == 'close':
                        raise ConnectionError('WebSocket disconnected')
                    if event['event'] == 'eof':
                        writer.write_eof()
                        return
                    block = base64.b64decode(event['data'], validate=True)
                    if not 0 < len(block) <= CHUNK:
                        raise ValueError('invalid browser data')
                    writer.write(block)
                    await writer.drain()
                    await self.send(op='ack', id=ident)

            async def both():
                directions=[asyncio.create_task(upload()),asyncio.create_task(download())]
                try:
                    await asyncio.gather(*directions)
                finally:
                    for direction in directions:
                        direction.cancel()
                    await asyncio.gather(*directions,return_exceptions=True)
            transfer = [asyncio.create_task(both()), asyncio.create_task(stream['closed'].wait())]
            done, _ = await asyncio.wait(transfer, return_when=asyncio.FIRST_COMPLETED)
            for finished in done:
                finished.result()
        except (OSError, ValueError, asyncio.TimeoutError):
            pass
        finally:
            for pending in transfer:
                pending.cancel()
            await asyncio.gather(*transfer, return_exceptions=True)
            self.streams.pop(ident, None)
            if stream and self.ready.is_set():
                with contextlib.suppress(OSError):
                    await self.send(op='close', id=ident)
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()
            self.tasks.discard(task)

    async def start(self):
        cfg = self.config
        url = urlsplit(cfg['origin'])
        if url.scheme != 'https' or url.path or url.query or url.fragment or not url.hostname or url.username:
            raise ValueError('BrowserLink origin must be a plain HTTPS origin')
        for service, address in cfg['listeners'].items():
            import ipaddress
            if not ipaddress.ip_address(endpoint(address)[0]).is_loopback:
                raise ValueError('BrowserLink local listeners must be loopback')
            self.servers.append(await asyncio.start_server(
                lambda r,w,s=service: self.accept(s,r,w), *endpoint(address)))
        self.supervisor = asyncio.create_task(self.supervise())

    async def stop(self):
        for server in self.servers:
            server.close()
            await server.wait_closed()
        if self.supervisor:
            self.supervisor.cancel()
            await asyncio.gather(self.supervisor, return_exceptions=True)
        for task in list(self.tasks):
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)


async def run(config):
    node = BrowserClient(config) if config['role']=='iran' else BrowserServer(config)
    done = asyncio.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        asyncio.get_running_loop().add_signal_handler(sig, done.set)
    try:
        await node.start()
        await done.wait()
    finally:
        await node.stop()


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--config', required=True)
    args = p.parse_args()
    asyncio.run(run(json.loads(Path(args.config).read_text())))

if __name__ == '__main__':
    main()
