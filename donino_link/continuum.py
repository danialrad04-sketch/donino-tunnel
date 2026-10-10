"""Continuum v2, phase 1: bounded TCP sessions surviving WSS lane replacement.

TLS is provided by the existing private-CA mutual TLS configuration. Recovery
only preserves sockets in this running process; it never recreates an origin
connection for an accepted stream. QUIC and cross-carrier switching are future
adapters, not features of this implementation.
"""
import argparse
import asyncio
import contextlib
import hashlib
import json
import secrets
import signal
import struct
import time
from collections import OrderedDict, deque
from pathlib import Path
from urllib.parse import urlsplit

from aiohttp import ClientSession, ClientTimeout, ClientError, WSMsgType, web
from .config import endpoint
from .mux import MuxNode, NAME, CHUNK, WINDOW, SLOTS, STREAMS, tls_context, close_writer

PROTOCOL = 'donino-continuum.v2'
HEADER = struct.Struct('!BIQ')
OPEN, READY, DATA, ACK, FIN, FIN_ACK, RESET = range(7)
MAX_MESSAGE = 32768  # Includes bounded JSON resume snapshots.
RECOVERY_SECONDS = 15
MAX_RETIRED = 128
MAX_OFFSET = (1 << 64) - 1


class ProtocolError(ValueError):
    """Authenticated peer violated the contract: terminate, do not resume."""


def packet(kind, sid, offset=0, body=b''):
    return HEADER.pack(kind, sid, offset) + body


def unpack(raw):
    if not isinstance(raw, bytes) or len(raw) < HEADER.size:
        raise ProtocolError('short frame')
    kind, sid, offset = HEADER.unpack(raw[:HEADER.size])
    body = raw[HEADER.size:]
    if kind not in range(7) or not sid or sid % 2 == 0:
        raise ProtocolError('invalid frame type or stream ID')
    if kind == OPEN:
        try:
            valid = not offset and NAME.fullmatch(body.decode('ascii'))
        except UnicodeError:
            valid = False
        if not valid:
            raise ProtocolError('invalid named service')
    elif kind == DATA:
        if not 0 < len(body) <= CHUNK or offset + len(body) > MAX_OFFSET:
            raise ProtocolError('invalid data range')
    elif body or (kind in (READY, RESET) and offset):
        raise ProtocolError('invalid control frame')
    return kind, sid, offset, body


def integer(value, maximum):
    return type(value) is int and 0 <= value <= maximum


def snapshot(value):
    if not isinstance(value, dict) or len(value) > STREAMS + MAX_RETIRED:
        raise ProtocolError('invalid recovery snapshot')
    result = {}
    for key, row in value.items():
        if not isinstance(key, str) or not key.isascii() or not key.isdecimal() or len(key) > 10:
            raise ProtocolError('invalid snapshot ID')
        sid = int(key)
        if not sid or sid % 2 == 0 or sid > 0xffffffff or str(sid) != key:
            raise ProtocolError('invalid snapshot ID')
        if not isinstance(row, list) or len(row) != 4 or not integer(row[0], MAX_OFFSET) or any(type(v) is not bool for v in row[1:]):
            raise ProtocolError('invalid recovery state')
        result[sid] = row
    return result


def hello(raw):
    if not isinstance(raw, str) or len(raw.encode()) > MAX_MESSAGE:
        raise ProtocolError('invalid greeting size')
    try:
        value = json.loads(raw)
    except (ValueError, RecursionError) as error:
        raise ProtocolError('invalid greeting JSON') from error
    if not isinstance(value, dict) or set(value) != {'version', 'id', 'token', 'epoch', 'resume', 'streams'}:
        raise ProtocolError('invalid greeting fields')
    if value['version'] != PROTOCOL or type(value['resume']) is not bool or not integer(value['epoch'], MAX_OFFSET) or not value['epoch']:
        raise ProtocolError('invalid greeting version or epoch')
    for key, size in [('id', 32), ('token', 64)]:
        text = value[key]
        if not isinstance(text, str) or len(text) != size or any(c not in '0123456789abcdef' for c in text):
            raise ProtocolError('invalid session credential')
    value['streams'] = snapshot(value['streams'])
    return value


class Flow:
    def __init__(self, session, sid, service, reader=None, writer=None):
        self.session, self.sid, self.service = session, sid, service
        self.reader, self.writer = reader, writer
        self.ready = asyncio.get_running_loop().create_future()
        self.pending = deque()
        self.tx_end = self.tx_ack = self.rx_next = self.rx_commit = 0
        self.rx_slots = SLOTS
        self.local_fin = self.fin_acked = self.rx_fin = self.remote_fin = False
        self.closed = self.counted = False
        self.incoming = asyncio.Queue(maxsize=SLOTS + 1)
        self.condition = asyncio.Condition()
        self.activity = time.monotonic()
        self.task = None

    def state(self):
        return [self.rx_commit, self.remote_fin, self.ready.done() and not self.ready.cancelled(), self.closed]

    async def acknowledge(self, offset, fin=False):
        if offset > self.tx_end:
            raise ProtocolError('ACK beyond sent data')
        async with self.condition:
            if offset > self.tx_ack:
                if not any(start + len(data) == offset for start, data in self.pending):
                    raise ProtocolError('ACK not at a frame boundary')
                while self.pending and self.pending[0][0] + len(self.pending[0][1]) <= offset:
                    self.pending.popleft()
                self.tx_ack = offset
            if fin:
                if not self.local_fin or offset != self.tx_end:
                    raise ProtocolError('unexpected FIN acknowledgment')
                self.fin_acked = True
            self.condition.notify_all()

    def receive_data(self, offset, body):
        end = offset + len(body)
        if end <= self.rx_next:
            return  # Previously queued/committed data; never write it twice.
        if self.rx_fin or offset != self.rx_next or end - self.rx_commit > WINDOW or self.rx_slots <= 0:
            raise ProtocolError('data gap, overlap or receive window exceeded')
        self.rx_next = end
        self.rx_slots -= 1
        self.incoming.put_nowait(body)

    def receive_fin(self, offset):
        if offset != self.rx_next:
            raise ProtocolError('FIN size mismatch')
        if not self.rx_fin:
            self.rx_fin = True
            self.incoming.put_nowait(None)

    async def produce(self):
        while not self.closed:
            async with self.condition:
                await self.condition.wait_for(lambda: self.closed or (len(self.pending) < SLOTS and self.tx_end - self.tx_ack < WINDOW))
                if self.closed:
                    return
                allowance = min(CHUNK, WINDOW - (self.tx_end - self.tx_ack))
            await self.session.available()
            block = await self.reader.read(allowance)
            await self.session.available()
            if not block:
                self.local_fin = True
                await self.session.send(FIN, self.sid, self.tx_end)
                return
            start = self.tx_end
            if start + len(block) > MAX_OFFSET:
                raise ProtocolError('stream offset exhausted')
            self.tx_end += len(block)
            self.pending.append((start, block))
            self.session.count(self, 'read', len(block))
            self.activity = time.monotonic()
            await self.session.send(DATA, self.sid, start, block)

    async def consume(self):
        while not self.closed:
            block = await self.incoming.get()
            if block is None:
                if not self.writer.can_write_eof():
                    raise OSError('TCP half-close unsupported')
                self.writer.write_eof()
                await self.writer.drain()
                self.remote_fin = True
                await self.session.send(FIN_ACK, self.sid, self.rx_commit)
                return
            self.writer.write(block)
            await self.writer.drain()
            self.rx_commit += len(block)
            self.rx_slots += 1
            self.activity = time.monotonic()
            self.session.count(self, 'write', len(block))
            await self.session.send(ACK, self.sid, self.rx_commit)

    async def guard(self):
        while True:
            await asyncio.sleep(1)
            if time.monotonic() - self.activity > self.session.node.idle_timeout:
                raise TimeoutError('idle flow')

    async def run(self):
        workers = []
        try:
            await asyncio.wait_for(asyncio.shield(self.ready), self.session.node.connect_timeout + self.session.node.recovery_timeout)
            if self.closed or self.session.closed:
                return
            self.counted = self.service != 'health'
            if self.counted:
                self.session.node.stats.active += 1
                self.session.node.stats.accepted += 1
            workers = [asyncio.create_task(self.produce()), asyncio.create_task(self.consume()), asyncio.create_task(self.guard())]
            pending = set(workers[:2])
            while pending:
                done, _ = await asyncio.wait(pending | {workers[2]}, return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    task.result()
                pending -= done
            async with self.condition:
                await asyncio.wait_for(self.condition.wait_for(lambda: self.closed or (not self.pending and self.fin_acked)), self.session.node.idle_timeout)
        except (OSError, ClientError, ValueError, asyncio.TimeoutError):
            self.closed = True
            with contextlib.suppress(OSError, ClientError, asyncio.TimeoutError):
                await self.session.send(RESET, self.sid)
        finally:
            self.closed = True
            for worker in workers:
                worker.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
            try:
                if self.writer:
                    await close_writer(self.writer)
            finally:
                self.session.retire(self)
                if self.counted:
                    self.session.node.stats.active -= 1


class DurableSession:
    def __init__(self, node, identity=None, token=None, peer=None):
        self.node = node
        self.identity = identity or secrets.token_hex(16)
        self.token = token or secrets.token_hex(32)
        self.peer = peer
        self.epoch = 0
        self.attempted = False
        self.streams = {}
        self.retired = OrderedDict()
        self.next_id = 1
        self.last_remote_id = 0
        self.ws = None
        self.connected = asyncio.Event()
        self.replayed = asyncio.Event()
        self.replay_task = None
        self.send_lock = asyncio.Lock()
        self.bind_lock = asyncio.Lock()
        self.tasks = set()
        self.closed = False
        self.disconnected_at = time.monotonic()
        self.created = time.monotonic()

    def spawn(self, coro):
        task = asyncio.create_task(coro)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        return task

    def states(self):
        rows = dict(self.retired)
        rows.update({sid: flow.state() for sid, flow in self.streams.items()})
        return {str(sid): row for sid, row in rows.items()}

    def retire(self, flow):
        if self.streams.pop(flow.sid, None) is not None:
            self.retired[flow.sid] = flow.state()
            while len(self.retired) > MAX_RETIRED:
                self.retired.popitem(last=False)
        flow.pending.clear()

    def count(self, flow, direction, size):
        if flow.service == 'health':
            return
        up = (self.node.role == 'iran' and direction == 'read') or (self.node.role == 'foreign' and direction == 'write')
        if up:
            self.node.stats.bytes_up += size
        else:
            self.node.stats.bytes_down += size

    async def available(self):
        if self.closed:
            raise ConnectionError('session closed')
        await self.connected.wait()
        await self.replayed.wait()
        if self.closed:
            raise ConnectionError('session closed')

    def detach(self, ws):
        if self.ws is ws:
            self.ws = None
            self.connected.clear()
            self.replayed.clear()
            self.disconnected_at = time.monotonic()

    async def write_raw(self, raw, expected=None):
        if self.closed:
            raise ConnectionError('session closed')
        async with self.send_lock:
            ws = self.ws
            if not ws or not self.connected.is_set() or (expected is not None and ws is not expected):
                return False
            try:
                await asyncio.wait_for(ws.send_bytes(raw), self.node.connect_timeout)
            except (OSError, ClientError, asyncio.TimeoutError):
                self.detach(ws)
                await ws.close()
                return False
        await asyncio.sleep(0)
        return True

    async def send(self, kind, sid, offset=0, body=b''):
        # State is recorded before this call; failed writes are replayed. The
        # reader must never wait for its own reconnect loop to replace a lane.
        await self.write_raw(packet(kind, sid, offset, body))

    async def apply_snapshot(self, rows):
        for sid, row in rows.items():
            if sid not in self.streams and sid not in self.retired:
                used = sid < self.next_id if self.node.role == 'iran' else sid <= self.last_remote_id
                if used:
                    continue  # A bounded tombstone may already have expired.
                # Client OPEN may have been lost before the foreign received it.
                if self.node.role != 'foreign' or row != [0, False, False, False] or sid <= self.last_remote_id:
                    raise ProtocolError('unknown stream in recovery')
        for sid, flow in list(self.streams.items()):
            row = rows.get(sid)
            if row is None:
                if self.node.role == 'iran' and not flow.ready.done():
                    continue
                flow.closed = True
                flow.task.cancel()
                continue
            offset, fin, ready, closed = row
            if closed:
                flow.closed = True
                flow.task.cancel()
                continue
            await flow.acknowledge(offset, fin)
            if self.node.role == 'iran' and ready and not flow.ready.done():
                flow.ready.set_result(True)

    async def replay(self, ws, queues):
        try:
            # Round-robin replay and concurrent receive avoid a full-duplex
            # deadlock when both sides have a full retransmission window.
            while queues:
                following = []
                for frames in queues:
                    raw = frames.popleft()
                    if not await self.write_raw(raw, expected=ws):
                        return
                    if raw[0] == DATA:
                        self.node.replayed_bytes += len(raw) - HEADER.size
                    if frames:
                        following.append(frames)
                queues = following
            if self.ws is ws and not self.closed:
                self.replayed.set()
        except (OSError, ClientError, asyncio.TimeoutError):
            self.detach(ws)
            await ws.close()

    async def bounded_replay(self, ws, queues):
        try:
            await asyncio.wait_for(self.replay(ws, queues), self.node.recovery_timeout)
        except asyncio.TimeoutError:
            self.detach(ws)
            await ws.close()

    async def attach(self, ws, rows):
        async with self.send_lock:
            old = self.ws
            self.connected.clear()
            self.replayed.clear()
            if self.replay_task:
                self.replay_task.cancel()
                await asyncio.gather(self.replay_task, return_exceptions=True)
            await self.apply_snapshot(rows)
            self.ws = ws
            queues = []
            for sid, flow in list(self.streams.items()):
                if flow.closed:
                    continue
                frames = deque()
                if self.node.role == 'iran' and not flow.ready.done():
                    frames.append(packet(OPEN, sid, body=flow.service.encode('ascii')))
                elif self.node.role == 'foreign' and flow.ready.done():
                    frames.append(packet(READY, sid))
                frames.append(packet(ACK, sid, flow.rx_commit))
                frames.extend(packet(DATA, sid, offset, block) for offset, block in flow.pending)
                if flow.local_fin:
                    frames.append(packet(FIN, sid, flow.tx_end))
                if flow.remote_fin:
                    frames.append(packet(FIN_ACK, sid, flow.rx_commit))
                queues.append(frames)
            for sid in rows:
                if sid not in self.streams and (sid in self.retired or (sid < self.next_id if self.node.role == 'iran' else sid <= self.last_remote_id)):
                    queues.append(deque([packet(RESET, sid)]))
            self.connected.set()
            self.replay_task = self.spawn(self.bounded_replay(ws, queues))
        if old and old is not ws:
            await asyncio.wait_for(old.close(), self.node.connect_timeout)

    async def open(self, service, reader, writer):
        await self.available()
        limit = STREAMS if service == 'health' else STREAMS - 1
        if self.closed or len(self.streams) >= limit or self.next_id > 0xffffffff:
            raise ConnectionError('session capacity')
        sid = self.next_id
        self.next_id += 2
        flow = Flow(self, sid, service, reader, writer)
        self.streams[sid] = flow
        flow.task = self.spawn(flow.run())
        await self.send(OPEN, sid, body=service.encode('ascii'))
        return flow.task

    async def accept(self, flow):
        try:
            flow.reader, flow.writer = await asyncio.wait_for(asyncio.open_connection(*endpoint(self.node.targets[flow.service])), self.node.connect_timeout)
            if flow.closed or self.closed:
                return
            flow.ready.set_result(True)
            await self.send(READY, flow.sid)
            await flow.run()
        except (OSError, ClientError, asyncio.TimeoutError):
            flow.closed = True
            with contextlib.suppress(OSError, ClientError, asyncio.TimeoutError):
                await self.send(RESET, flow.sid)
        finally:
            if self.streams.get(flow.sid) is flow:
                flow.closed = True
                try:
                    if flow.writer:
                        await close_writer(flow.writer)
                finally:
                    self.retire(flow)

    async def dispatch(self, kind, sid, offset, body):
        flow = self.streams.get(sid)
        if kind == OPEN:
            if self.node.role != 'foreign':
                raise ProtocolError('OPEN direction')
            service = body.decode('ascii')
            if flow:
                if flow.service != service:
                    raise ProtocolError('OPEN changes existing target')
                if flow.ready.done():
                    await self.send(READY, sid)
                return
            if sid in self.retired:
                await self.send(RESET, sid)
                return
            if sid <= self.last_remote_id:
                raise ProtocolError('reused stream ID')
            self.last_remote_id = sid
            limit = STREAMS if service == 'health' else STREAMS - 1
            if service not in self.node.targets or len(self.streams) >= limit:
                self.retired[sid] = [0, False, False, True]
                while len(self.retired) > MAX_RETIRED:
                    self.retired.popitem(last=False)
                await self.send(RESET, sid)
                return
            flow = Flow(self, sid, service)
            self.streams[sid] = flow
            flow.task = self.spawn(self.accept(flow))
            return
        if not flow:
            if sid in self.retired:
                return
            raise ProtocolError('unknown stream')
        if kind == RESET:
            flow.closed = True
            flow.task.cancel()
        elif kind == READY:
            if self.node.role != 'iran':
                raise ProtocolError('READY direction')
            if not flow.ready.done():
                flow.ready.set_result(True)
        elif kind == ACK:
            await flow.acknowledge(offset)
        elif not flow.ready.done():
            raise ProtocolError('unaccepted stream')
        elif kind == DATA:
            before = flow.rx_next
            flow.receive_data(offset, body)
            if before == flow.rx_next:
                await self.send(ACK, sid, flow.rx_commit)
        elif kind == FIN:
            flow.receive_fin(offset)
            if flow.remote_fin:
                await self.send(FIN_ACK, sid, flow.rx_commit)
        elif kind == FIN_ACK:
            await flow.acknowledge(offset, True)

    async def receive(self, ws):
        try:
            async for message in ws:
                if self.ws is not ws or self.closed:
                    break  # Epoch fencing: a replaced lane has no authority.
                if message.type == WSMsgType.ERROR:
                    break
                if message.type != WSMsgType.BINARY:
                    raise ProtocolError('binary frames required')
                await self.dispatch(*unpack(message.data))
        except (ProtocolError, asyncio.QueueFull) as error:
            self.node.last_error = str(error)
            await self.close(code=1008)
        except (OSError, ClientError, asyncio.TimeoutError):
            pass
        finally:
            self.detach(ws)
            if ws.close_code == 1008 and not self.closed:
                await self.close()
            await ws.close()

    async def close(self, code=1000):
        if self.closed:
            return
        self.closed = True
        self.connected.set()  # Wake blocked tasks, which then fail closed.
        self.replayed.set()
        tasks = list(self.tasks)
        for flow in list(self.streams.values()):
            flow.closed = True
            if flow.writer:
                flow.writer.close()
        for task in tasks:
            task.cancel()
        if self.ws:
            with contextlib.suppress(OSError, ClientError, asyncio.TimeoutError):
                await asyncio.wait_for(self.ws.close(code=code), self.node.connect_timeout)
        await asyncio.gather(*tasks, return_exceptions=True)
        self.streams.clear()
        self.retired.clear()
        self.node.sessions.discard(self)


class ContinuumNode(MuxNode):
    def __init__(self, config):
        super().__init__(config)
        self.recovery_timeout = config.get('recovery_timeout', RECOVERY_SECONDS)
        if type(self.recovery_timeout) not in (int, float) or not 1 <= self.recovery_timeout <= 60:
            raise ValueError('recovery_timeout must be 1..60 seconds')
        self.identities = {}
        self.recoveries = self.expired = self.replayed_bytes = 0
        self.stats.details = self.telemetry
        self.pending_links = 0

    def telemetry(self):
        sessions = [s for s in self.sessions if not s.closed]
        return {'name': PROTOCOL,
                'connected_lanes': sum(s.connected.is_set() for s in sessions),
                'recovering_sessions': sum(not s.connected.is_set() or not s.replayed.is_set() for s in sessions),
                'recoveries': self.recoveries, 'expired': self.expired,
                'replayed_bytes': self.replayed_bytes,
                'pending_bytes': sum(f.tx_end - f.tx_ack for s in sessions for f in s.streams.values()),
                'recovery_seconds': self.recovery_timeout}

    async def server_link(self, request):
        if self.stopping or self.pending_links >= 8:
            raise web.HTTPServiceUnavailable()
        self.pending_links += 1
        ws = web.WebSocketResponse(protocols=[PROTOCOL], compress=False, heartbeat=2, max_msg_size=MAX_MESSAGE + 1)
        session = None
        admitted = False
        try:
            await ws.prepare(request)
            if ws.ws_protocol != PROTOCOL:
                raise ProtocolError('subprotocol required')
            ssl_object = request.transport.get_extra_info('ssl_object')
            certificate = ssl_object.getpeercert(binary_form=True) if ssl_object else None
            if not certificate:
                raise ProtocolError('mutual TLS required')
            peer = hashlib.sha256(certificate).digest()
            first = await asyncio.wait_for(ws.receive(), self.connect_timeout)
            if first.type != WSMsgType.TEXT:
                raise ProtocolError('greeting required')
            value = hello(first.data)
            session = self.identities.get(value['id'])
            if value['resume']:
                if not session or session.closed or session.peer != peer or not secrets.compare_digest(session.token, value['token']) or value['epoch'] <= session.epoch:
                    raise ProtocolError('resume denied')
                if not session.connected.is_set() and time.monotonic() - session.disconnected_at >= self.recovery_timeout:
                    raise ProtocolError('resume expired')
            else:
                if session or value['streams'] or len(self.sessions) >= 8:
                    raise ProtocolError('new session denied')
                session = DurableSession(self, value['id'], value['token'], peer)
                self.identities[session.identity] = session
                self.sessions.add(session)
            async with session.bind_lock:
                # Recheck after waiting: two concurrent handshakes must not
                # attach an older epoch after a newer handshake has committed.
                if session.closed or value['epoch'] <= session.epoch:
                    raise ProtocolError('resume superseded')
                admitted = True
                # Commit epoch before any await: a second handshake cannot reuse it.
                session.epoch = value['epoch']
                response = {'version': PROTOCOL, 'epoch': session.epoch, 'streams': session.states()}
                await ws.send_str(json.dumps(response, separators=(',', ':')))
                await session.attach(ws, value['streams'])
                if value['resume']:
                    self.recoveries += 1
            await session.receive(ws)
        except ProtocolError as error:
            self.last_error = str(error)
            # A denied credential/epoch must never kill the legitimate session.
            # Invalid state from an admitted peer does terminate its own session.
            if admitted:
                await session.close(code=1008)
            await ws.close(code=1008)
        except (OSError, ClientError, asyncio.TimeoutError):
            await ws.close()
        finally:
            if session:
                session.detach(ws)
            self.pending_links -= 1
        return ws

    async def connect(self, session):
        session.epoch += 1  # Monotonic attempts also handle a lost HELLO response.
        value = {'version': PROTOCOL, 'id': session.identity, 'token': session.token, 'epoch': session.epoch, 'resume': session.attempted, 'streams': session.states()}
        ws = await self.http.ws_connect(self.config['url'], ssl=tls_context(self.config), protocols=[PROTOCOL], compress=0, heartbeat=2, max_msg_size=MAX_MESSAGE + 1)
        session.attempted = True
        try:
            if ws.protocol != PROTOCOL:
                raise ProtocolError('subprotocol rejected')
            await ws.send_str(json.dumps(value, separators=(',', ':')))
            first = await asyncio.wait_for(ws.receive(), self.connect_timeout)
            if first.type in (WSMsgType.CLOSE, WSMsgType.CLOSED) and (first.data == 1008 or ws.close_code == 1008):
                raise ProtocolError('foreign rejected recovery')
            if first.type != WSMsgType.TEXT:
                raise ConnectionError('greeting interrupted')
            try:
                response = json.loads(first.data)
            except (ValueError, RecursionError) as error:
                raise ProtocolError('invalid greeting reply') from error
            if not isinstance(response, dict) or set(response) != {'version', 'epoch', 'streams'} or response['version'] != PROTOCOL or type(response['epoch']) is not int or response['epoch'] != session.epoch:
                raise ProtocolError('greeting reply mismatch')
            await session.attach(ws, snapshot(response['streams']))
            if value['resume']:
                self.recoveries += 1
            return ws
        except BaseException:
            session.detach(ws)
            await ws.close()
            raise

    async def maintain(self, session):
        try:
            while not self.stopping and not session.closed:
                if time.monotonic() - session.disconnected_at >= self.recovery_timeout:
                    self.expired += 1
                    break
                try:
                    ws = await asyncio.wait_for(self.connect(session), min(self.connect_timeout, self.recovery_timeout - (time.monotonic() - session.disconnected_at)))
                    await session.receive(ws)
                except ProtocolError as error:
                    self.last_error = str(error)
                    break
                except (OSError, ClientError, asyncio.TimeoutError):
                    await asyncio.sleep(.2)
        finally:
            await session.close()

    async def lane(self, index):
        async with self.pool_locks[index]:
            session = self.pool[index]
            if not session or session.closed:
                session = DurableSession(self)
                self.pool[index] = session
                self.sessions.add(session)
                task = asyncio.create_task(self.maintain(session))
                self.tasks.add(task)
                task.add_done_callback(self.tasks.discard)
            await asyncio.wait_for(session.available(), self.connect_timeout + self.recovery_timeout)
            return session

    async def reap(self):
        while not self.stopping:
            await asyncio.sleep(.2)
            for session in list(self.sessions):
                if not session.connected.is_set() and time.monotonic() - session.disconnected_at >= self.recovery_timeout:
                    self.expired += 1
                    await session.close()
            for identity, session in list(self.identities.items()):
                if session.closed:
                    self.identities.pop(identity, None)

    async def start(self):
        if self.role == 'iran':
            url = urlsplit(self.config['url'])
            if url.scheme != 'wss' or not url.hostname or url.path != '/continuum' or url.query or url.fragment or url.username:
                raise ValueError('Continuum requires direct wss /continuum URL')
        try:
            if self.role == 'foreign':
                app = web.Application()
                app.router.add_get('/continuum', self.server_link)
                self.runner = web.AppRunner(app)
                await self.runner.setup()
                host, port = endpoint(self.config['listen'])
                await web.TCPSite(self.runner, host, port, ssl_context=tls_context(self.config, True)).start()
                task = asyncio.create_task(self.reap())
                self.tasks.add(task)
                task.add_done_callback(self.tasks.discard)
            else:
                self.http = ClientSession(timeout=ClientTimeout(total=self.connect_timeout), trust_env=False)
                for service, address in self.listeners.items():
                    self.servers.append(await asyncio.start_server(lambda r, w, s=service: self.client_stream(r, w, s), *endpoint(address)))
            await self.stats.start()
        except BaseException:
            await self.stop()
            raise


async def run(config):
    node = ContinuumNode(config)
    done = asyncio.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        asyncio.get_running_loop().add_signal_handler(sig, done.set)
    try:
        await node.start()
        await done.wait()
    finally:
        await node.stop()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    asyncio.run(run(json.loads(Path(parser.parse_args().config).read_text())))
