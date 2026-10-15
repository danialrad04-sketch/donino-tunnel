"""Bounded UDP associations over native Paqet UDP or existing stream carriers.

The foreign socket belongs to an authenticated association, not a carrier. A
carrier change keeps that socket but never retransmits old application packets.
All relay listeners are loopback-only; encryption is provided by the carrier.
"""
import asyncio
import contextlib
import hmac
import secrets
import struct
import time

from .config import endpoint

MAX_PAYLOAD = 1400
QUEUE = 32
MAX_ASSOCIATIONS = 128
IDLE = 120
HEADER = struct.Struct('!4s16sQQ')
MAX_FRAME = HEADER.size + MAX_PAYLOAD + 32


def encode(key, service, direction, identity, sequence, data, probe=False):
    if not 0 < len(data) <= MAX_PAYLOAD:
        raise ValueError('UDP payload must contain 1 to 1400 bytes')
    body = HEADER.pack(b'DUH1' if probe else b'DUD1', identity, sequence, int(time.time())) + data
    return body + hmac.digest(bytes.fromhex(key), service.encode() + direction + body, 'sha256')


def decode(key, service, direction, frame):
    if not HEADER.size + 32 < len(frame) <= MAX_FRAME:
        raise ValueError('invalid UDP frame size')
    body, signature = frame[:-32], frame[-32:]
    expected = hmac.digest(bytes.fromhex(key), service.encode() + direction + body, 'sha256')
    if not hmac.compare_digest(signature, expected):
        raise ValueError('UDP authentication failed')
    magic, identity, sequence, timestamp = HEADER.unpack_from(body)
    if magic not in (b'DUD1', b'DUH1') or abs(time.time() - timestamp) > 30:
        raise ValueError('expired UDP frame')
    return identity, sequence, body[HEADER.size:], magic == b'DUH1'


async def probe(address, key, service, timeout=2, native=False):
    """Fresh authenticated relay round trip; no application UDP probe is sent."""
    identity, nonce = secrets.token_bytes(16), secrets.token_bytes(32)
    frame = encode(key, service, b'up', identity, 0, nonce, probe=True)
    writer = socket = None
    started = time.monotonic()

    async def exchange():
        nonlocal writer, socket
        if native:
            future = asyncio.get_running_loop().create_future()
            def receive(data, address):
                if not future.done():
                    try:
                        result = decode(key, service, b'down', data)
                        if result == (identity, 0, nonce, True):
                            future.set_result(data)
                    except ValueError:
                        pass
            socket, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: Protocol(receive), remote_addr=endpoint(address))
            socket.sendto(frame)
            response = await future
        else:
            reader, writer = await asyncio.open_connection(*endpoint(address))
            write_frame(writer, frame)
            await writer.drain()
            response = await read_frame(reader)
        if decode(key, service, b'down', response) != (identity, 0, nonce, True):
            raise ValueError('UDP relay probe mismatch')
        return round((time.monotonic() - started) * 1000, 2)
    try:
        return await asyncio.wait_for(exchange(), timeout)
    except asyncio.IncompleteReadError as error:
        raise ConnectionError('UDP relay connection closed before the probe response') from error
    finally:
        if socket:
            socket.close()
        if writer:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()


class ReplayWindow:
    """Accept reordered packets once, with constant memory."""
    def __init__(self):
        self.high = -1
        self.bits = 0

    def accept(self, sequence):
        if sequence > self.high:
            self.bits = ((self.bits << min(sequence - self.high, 256)) | 1) & ((1 << 256) - 1)
            self.high = sequence
            return True
        distance = self.high - sequence
        if distance >= 256 or self.bits & (1 << distance):
            return False
        self.bits |= 1 << distance
        return True


async def read_frame(reader):
    size = struct.unpack('!H', await reader.readexactly(2))[0]
    if not HEADER.size + 32 < size <= MAX_FRAME:
        raise ValueError('invalid UDP stream frame size')
    return await reader.readexactly(size)


def write_frame(writer, frame):
    writer.write(struct.pack('!H', len(frame)) + frame)


class Protocol(asyncio.DatagramProtocol):
    def __init__(self, receive):
        self.receive = receive

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, address):
        self.receive(data, address)


class ForeignFlow:
    def __init__(self, relay, identity):
        self.relay, self.identity = relay, identity
        self.last = time.monotonic()
        self.replay = ReplayWindow()
        # A restarted foreign process must not reuse response sequence numbers
        # while an Iran association still has its previous replay window.
        self.sequence = time.time_ns()
        self.route = None
        self.socket = None
        self.queue = asyncio.Queue(QUEUE)
        self.task = asyncio.create_task(self.run())

    def response(self, data, address):
        if not 0 < len(data) <= MAX_PAYLOAD or not self.route:
            self.relay.dropped += 1
            return
        frame = encode(self.relay.key, self.relay.service, b'down', self.identity, self.sequence, data)
        self.sequence += 1
        if self.route(frame):
            self.relay.bytes_down += len(data)
            self.last = time.monotonic()
        else:
            self.relay.dropped += 1

    async def run(self):
        try:
            self.socket, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: Protocol(self.response), remote_addr=endpoint(self.relay.target))
            while True:
                try:
                    remaining = max(.001, self.last + self.relay.idle - time.monotonic())
                    data = await asyncio.wait_for(self.queue.get(), remaining)
                except asyncio.TimeoutError:
                    if time.monotonic() - self.last < self.relay.idle:
                        continue
                    break
                self.socket.sendto(data)
        except (OSError, asyncio.TimeoutError):
            pass
        finally:
            if self.socket:
                self.socket.close()
            self.relay.flows.pop(self.identity, None)


class DatagramRelay:
    def __init__(self, service, listen, target, key, limit=MAX_ASSOCIATIONS, idle=IDLE, pool=None):
        self.service, self.listen, self.target, self.key = service, listen, target, key
        self.limit, self.idle = limit, idle
        self.flows, self.connections = {}, set()
        self.bytes_up = self.bytes_down = self.dropped = 0
        self.server = self.socket = None
        self.pool = pool if pool is not None else [self]

    def receive(self, frame, route):
        try:
            identity, sequence, data, health = decode(self.key, self.service, b'up', frame)
        except ValueError:
            self.dropped += 1
            return
        if health:
            route(encode(self.key, self.service, b'down', identity, sequence, data, probe=True))
            return
        flow = self.flows.get(identity)
        if flow is None:
            if sum(len(r.flows) for r in self.pool) >= self.limit:
                self.dropped += 1
                return
            flow = self.flows[identity] = ForeignFlow(self, identity)
        if not flow.replay.accept(sequence):
            self.dropped += 1
            return
        if sequence == flow.replay.high:
            flow.route = route
        flow.last = time.monotonic()
        try:
            flow.queue.put_nowait(data)
            self.bytes_up += len(data)
        except asyncio.QueueFull:
            self.dropped += 1

    async def stream(self, reader, writer):
        task = asyncio.current_task()
        # Reserve bounded headroom for health probes at association capacity.
        if sum(len(r.connections) for r in self.pool) >= self.limit + 16:
            writer.close()
            await writer.wait_closed()
            return
        self.connections.add(task)
        responses = asyncio.Queue(QUEUE)

        def route(frame):
            if task.done() or writer.is_closing() or responses.full():
                return False
            responses.put_nowait(frame)
            return True

        async def send():
            while True:
                frame = await responses.get()
                write_frame(writer, frame)
                await asyncio.wait_for(writer.drain(), 5)

        sender = asyncio.create_task(send())
        try:
            while True:
                frame_task = asyncio.create_task(read_frame(reader))
                done, _ = await asyncio.wait((frame_task, sender), timeout=self.idle,
                                             return_when=asyncio.FIRST_COMPLETED)
                if frame_task not in done:
                    frame_task.cancel()
                    await asyncio.gather(frame_task, return_exceptions=True)
                    break
                self.receive(frame_task.result(), route)
        except (OSError, ValueError, asyncio.IncompleteReadError):
            pass
        finally:
            sender.cancel()
            if 'frame_task' in locals():
                frame_task.cancel()
                await asyncio.gather(frame_task, return_exceptions=True)
            await asyncio.gather(sender, return_exceptions=True)
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()
            self.connections.discard(task)

    async def start(self):
        self.server = await asyncio.start_server(self.stream, *endpoint(self.listen))
        try:
            def receive(frame, address):
                def route(response):
                    self.socket.sendto(response, address)
                    return True
                self.receive(frame, route)
            self.socket, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: Protocol(receive), local_addr=endpoint(self.listen))
        except BaseException:
            await self.stop()
            raise

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        if self.socket:
            self.socket.close()
        tasks = [f.task for f in self.flows.values()] + list(self.connections)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    def snapshot(self):
        return {'service': self.service, 'active': len(self.flows), 'bytes_up': self.bytes_up,
                'bytes_down': self.bytes_down, 'dropped': self.dropped, 'limit': self.limit}


class Association:
    def __init__(self, listener, address):
        self.listener, self.address = listener, address
        self.identity, self.sequence = secrets.token_bytes(16), 0
        self.replay = ReplayWindow()
        self.last = time.monotonic()
        self.queue = asyncio.Queue(QUEUE)
        self.writer = self.native = self.reader_task = None
        self.path = None
        self.task = asyncio.create_task(self.run())

    def response(self, frame, address=None):
        try:
            identity, sequence, data, health = decode(self.listener.gateway.config['health_key'],
                                              self.listener.service['id'], b'down', frame)
            if health or identity != self.identity or not self.replay.accept(sequence):
                return
            self.listener.socket.sendto(data, self.address)
            self.listener.bytes_down += len(data)
            self.last = time.monotonic()
        except (ValueError, OSError):
            self.listener.dropped += 1

    async def close_path(self):
        if self.native:
            self.native.close()
            self.native = None
        if self.reader_task:
            self.reader_task.cancel()
            await asyncio.gather(self.reader_task, return_exceptions=True)
            self.reader_task = None
        if self.writer:
            self.writer.close()
            with contextlib.suppress(OSError):
                await self.writer.wait_closed()
            self.writer = None

    def candidates(self):
        gateway = self.listener.gateway
        # Draining preserves established associations on their current path.
        paths = gateway.candidates(self.listener.service['id'])
        if self.path and self.path.mode == 'draining' and self.path.healthy:
            paths.insert(0, self.path)
        return paths

    async def connect(self, path):
        service = self.listener.service['id']
        address = path.config.get('udp_backends', {}).get(service)
        if address and path.remote.get('udp_ok') is True:
            self.native, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: Protocol(self.response), remote_addr=endpoint(address))
        else:
            reader, self.writer = await asyncio.wait_for(
                asyncio.open_connection(*endpoint(path.config['backends'][service])),
                self.listener.gateway.policy['connect_timeout'])

            async def receive():
                while True:
                    self.response(await read_frame(reader))
            self.reader_task = asyncio.create_task(receive())

    async def run(self):
        gateway = self.listener.gateway
        try:
            while True:
                try:
                    remaining = max(.001, self.last + self.listener.idle - time.monotonic())
                    data, created = await asyncio.wait_for(self.queue.get(), remaining)
                except asyncio.TimeoutError:
                    if time.monotonic() - self.last < self.listener.idle:
                        continue
                    break
                self.last = time.monotonic()
                if time.monotonic() - created > 2:
                    self.listener.dropped += 1
                    continue
                paths = self.candidates()
                selected = paths[0] if paths else None
                native_failed = self.native and self.path.remote.get('udp_ok') is not True
                broken = self.reader_task and self.reader_task.done()
                if self.path != selected or native_failed or broken:
                    await self.close_path()
                    self.path = None
                if not self.native and not self.writer:
                    for path in paths:
                        try:
                            await self.connect(path)
                            if self.listener.last_path and self.listener.last_path != path.config['id']:
                                self.listener.failovers += 1
                            self.listener.last_path = path.config['id']
                            self.path = path
                            break
                        except (OSError, asyncio.TimeoutError):
                            await self.close_path()
                if not self.path or time.monotonic() - created > 2:
                    self.listener.dropped += 1
                    continue
                frame = encode(gateway.config['health_key'], self.listener.service['id'],
                               b'up', self.identity, self.sequence, data)
                self.sequence += 1
                try:
                    if self.native:
                        self.native.sendto(frame)
                    else:
                        write_frame(self.writer, frame)
                        await asyncio.wait_for(self.writer.drain(), 2)
                    self.listener.bytes_up += len(data)
                except (OSError, asyncio.TimeoutError):
                    # Uncertain UDP delivery is dropped, never replayed.
                    self.listener.dropped += 1
                    await self.close_path()
                    self.path = None
        except (OSError, asyncio.TimeoutError, ValueError):
            pass
        finally:
            await self.close_path()
            self.listener.flows.pop(self.address, None)


class DatagramListener:
    def __init__(self, gateway, service):
        self.gateway, self.service = gateway, service
        self.flows = {}
        self.socket = None
        self.idle = gateway.policy.get('udp_idle_timeout', IDLE)
        self.bytes_up = self.bytes_down = self.dropped = self.accepted = self.rejected = self.failovers = 0
        self.last_path = None

    def receive(self, data, address):
        if not 0 < len(data) <= MAX_PAYLOAD:
            self.dropped += 1
            return
        flow = self.flows.get(address)
        if flow is None:
            count = sum(len(l.flows) for l in self.gateway.udp_listeners)
            if self.gateway.paused or count >= self.gateway.policy.get('max_udp_associations', MAX_ASSOCIATIONS) or self.gateway.admission_reason():
                self.rejected += 1
                return
            flow = self.flows[address] = Association(self, address)
            self.accepted += 1
        try:
            flow.queue.put_nowait((data, time.monotonic()))
        except asyncio.QueueFull:
            self.dropped += 1

    async def start(self):
        self.socket, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: Protocol(self.receive), local_addr=endpoint(self.service['listen']))

    async def stop(self):
        if self.socket:
            self.socket.close()
        tasks = [f.task for f in self.flows.values()]
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    def snapshot(self):
        return {'service': self.service['id'], 'active': len(self.flows), 'accepted': self.accepted,
                'rejected': self.rejected, 'dropped': self.dropped, 'bytes_up': self.bytes_up,
                'bytes_down': self.bytes_down, 'route_changes': self.failovers, 'selected': self.last_path,
                'max_payload': MAX_PAYLOAD}
