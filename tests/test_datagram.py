import asyncio
import contextlib
import json
import socket
import tempfile
import time
import unittest
from pathlib import Path

from donino_link.config import atomic_json, load_config
from donino_link.datagram import DatagramRelay, Protocol, ReplayWindow, encode, decode, probe, read_frame, write_frame
from donino_link.gateway import Gateway
from donino_link.management import node_files, validated_node
from donino_link.plan import make_plan, TRANSPORTS
from donino_link.store import Store

KEY = 'ad' * 32


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class WireTests(unittest.TestCase):
    def test_authentication_direction_service_and_freshness(self):
        frame = encode(KEY, 'vpn', b'up', b'a'*16, 7, b'hello')
        self.assertEqual(decode(KEY, 'vpn', b'up', frame), (b'a'*16, 7, b'hello', False))
        for key, service, direction, data in [
            ('ba'*32, 'vpn', b'up', frame), (KEY, 'other', b'up', frame),
            (KEY, 'vpn', b'down', frame), (KEY, 'vpn', b'up', frame[:-1]+bytes([frame[-1]^1])),
        ]:
            with self.subTest(service=service, direction=direction), self.assertRaises(ValueError):
                decode(key, service, direction, data)
        from unittest.mock import patch
        with patch('donino_link.datagram.time.time', return_value=time.time()+60), self.assertRaises(ValueError):
            decode(KEY, 'vpn', b'up', frame)
        for data in (b'', b'x'*1401):
            with self.assertRaises(ValueError):encode(KEY, 'vpn', b'up', b'a'*16, 0, data)

    def test_reordered_packets_are_once_only_with_bounded_window(self):
        window = ReplayWindow()
        for value in (3, 1, 2, 0, 259, 258, 4):self.assertTrue(window.accept(value))
        for value in (3, 1, 2, 259, 4):self.assertFalse(window.accept(value))
        self.assertLessEqual(window.bits.bit_length(), 256)


class LiveTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name)/'state.sqlite3')
        self.sockets = []
        self.origin_sources = []
        def echo(data, source):
            self.origin_sources.append(source)
            self.origin.sendto(data, source)
        self.origin, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: Protocol(echo), local_addr=('127.0.0.1', 0))
        origin_port = self.origin.get_extra_info('sockname')[1]
        self.address = '127.0.0.1:'+str(port())
        self.relay = DatagramRelay('vpn', self.address, f'127.0.0.1:{origin_port}', KEY)
        await self.relay.start()
        self.config = {'schema':1, 'role':'iran', 'health_key':KEY,
            'services':[{'id':'vpn', 'listen':'127.0.0.1:'+str(port()), 'protocol':'udp'}],
            'paths': [{'id':name, 'priority':i, 'health':'127.0.0.1:1', 'backends':{'vpn':self.address},
                       **({'udp_backends':{'vpn':self.address}} if i==0 else {})}
                      for i,name in enumerate(('primary','backup'))],
            'policy': {'connect_timeout':.3}, 'panel':{}, 'state_db':str(Path(self.temp.name)/'state.sqlite3')}
        self.gateway = Gateway(self.config, self.store)
        async def monitor():await asyncio.Event().wait()
        self.gateway.monitor = monitor
        for path in self.gateway.paths.values():
            path.healthy = True
            path.remote = {'udp_ok':True}
        await self.gateway.start()

    async def asyncTearDown(self):
        await self.gateway.stop()
        await self.relay.stop()
        self.origin.close()
        for sock in self.sockets:sock.close()
        self.store.close()
        self.temp.cleanup()

    async def client(self):
        queue = asyncio.Queue()
        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: Protocol(lambda data, source:queue.put_nowait(data)),
            remote_addr=tuple([*self.gateway.udp_listeners[0].socket.get_extra_info('sockname')[:2]]))
        self.sockets.append(transport)
        return transport, queue

    async def exchange(self, client, payload):
        sock, queue = client
        sock.sendto(payload)
        self.assertEqual(await asyncio.wait_for(queue.get(), 2), payload)

    async def test_native_failure_switches_to_stream_without_reopening_origin_socket(self):
        client = await self.client()
        await self.exchange(client, b'native')
        source = self.origin_sources[-1]
        self.gateway.paths['primary'].healthy = False
        await self.exchange(client, b'fallback')
        self.assertEqual(self.origin_sources[-1], source)
        self.assertEqual(len(self.relay.flows), 1)
        self.assertEqual(self.gateway.udp_listeners[0].snapshot()['route_changes'], 1)
        self.assertEqual(self.gateway.udp_listeners[0].snapshot()['selected'], 'backup')

    async def test_fifty_clients_have_isolated_bidirectional_associations(self):
        clients = [await self.client() for _ in range(50)]
        await asyncio.gather(*(self.exchange(client, bytes([i])*1200) for i,client in enumerate(clients)))
        self.assertEqual(len(set(self.origin_sources)), 50)
        self.assertEqual(len(self.relay.flows), 50)
        self.gateway.paths['primary'].healthy = False
        await asyncio.gather(*(self.exchange(client, bytes([i])+b'after') for i,client in enumerate(clients)))
        self.assertEqual(len(set(self.origin_sources)), 50)
        self.assertEqual(self.gateway.udp_listeners[0].snapshot()['active'], 50)

    async def test_admission_rejects_new_clients_and_preserves_existing(self):
        self.gateway.configure({'max_udp_associations':1})
        first, second = await self.client(), await self.client()
        await self.exchange(first, b'established')
        self.assertTrue(self.gateway.snapshot()['admission']['udp_full'])
        second[0].sendto(b'reject')
        with self.assertRaises(asyncio.TimeoutError):await asyncio.wait_for(second[1].get(), .05)
        self.gateway._memory_checked = time.monotonic()
        self.gateway._memory_available = 0
        await self.exchange(first, b'preserved-under-pressure')
        self.assertEqual(self.gateway.snapshot()['admission']['reason'], 'memory-pressure')
        self.assertEqual(self.gateway.udp_listeners[0].rejected, 1)

    async def test_pause_preserves_existing_and_idle_reclaims_associations(self):
        listener = self.gateway.udp_listeners[0]
        listener.idle = .1
        first = await self.client()
        await self.exchange(first, b'first')
        self.gateway.paused = True
        await self.exchange(first, b'existing')
        second = await self.client()
        second[0].sendto(b'new')
        for _ in range(100):
            if not listener.flows:break
            await asyncio.sleep(.01)
        self.assertEqual(len(listener.flows), 0)
        self.assertEqual(listener.rejected, 1)

    async def test_probe_is_authenticated_and_never_sent_to_the_application(self):
        for native in (False, True):
            self.assertGreaterEqual(await probe(self.address, KEY, 'vpn', native=native), 0)
        self.assertEqual(self.origin_sources, [])
        self.assertEqual(len(self.relay.flows), 0)
        with self.assertRaises((asyncio.TimeoutError, ValueError)):
            await probe(self.address, 'ba'*32, 'vpn', timeout=.05)

    async def test_probe_connection_loss_is_a_network_failure(self):
        async def drop(reader, writer):
            await reader.read(1)
            writer.close()
            await writer.wait_closed()
        server=await asyncio.start_server(drop,'127.0.0.1',0)
        try:
            address='127.0.0.1:'+str(server.sockets[0].getsockname()[1])
            with self.assertRaises(ConnectionError):await probe(address,KEY,'vpn')
        finally:
            server.close();await server.wait_closed()

    async def test_duplicate_and_reordered_native_frames_do_not_duplicate_application_data(self):
        queue = asyncio.Queue()
        sock, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: Protocol(lambda data, address:queue.put_nowait(data)), remote_addr=('127.0.0.1', int(self.address.split(':')[1])))
        self.sockets.append(sock)
        for sequence in (2, 0, 1, 2, 1):sock.sendto(encode(KEY, 'vpn', b'up', b'c'*16, sequence, str(sequence).encode()))
        for _ in range(3):await asyncio.wait_for(queue.get(), 1)
        self.assertEqual(len(self.origin_sources), 3)
        self.assertEqual(self.relay.dropped, 2)

    async def test_late_old_path_packet_does_not_steal_the_response_route(self):
        native=asyncio.Queue()
        sock,_=await asyncio.get_running_loop().create_datagram_endpoint(
            lambda:Protocol(lambda data,address:native.put_nowait(data)),
            remote_addr=('127.0.0.1',int(self.address.split(':')[1])))
        self.sockets.append(sock)
        reader,writer=await asyncio.open_connection('127.0.0.1',int(self.address.split(':')[1]))
        try:
            write_frame(writer,encode(KEY,'vpn',b'up',b'z'*16,5,b'new-path'))
            await writer.drain();await asyncio.wait_for(read_frame(reader),1)
            sock.sendto(encode(KEY,'vpn',b'up',b'z'*16,4,b'late-old-path'))
            response=decode(KEY,'vpn',b'down',await asyncio.wait_for(read_frame(reader),1))
            self.assertEqual(response[2],b'late-old-path')
            self.assertTrue(native.empty())
        finally:
            writer.close();await writer.wait_closed()

    async def test_new_datagrams_recover_after_foreign_process_state_is_lost(self):
        client=await self.client()
        await self.exchange(client,b'before-restart')
        target=self.relay.target
        await self.relay.stop()
        self.relay=DatagramRelay('vpn',self.address,target,KEY)
        await self.relay.start()
        await self.exchange(client,b'after-restart')

    async def test_oversize_and_flood_queues_are_bounded(self):
        client = await self.client()
        await self.exchange(client, b'valid')
        listener = self.gateway.udp_listeners[0]
        address = next(iter(listener.flows))
        for _ in range(500):listener.receive(b'x'*1200, address)
        listener.receive(b'x'*1401, address)
        self.assertLessEqual(listener.flows[address].queue.qsize(), 32)
        self.assertGreaterEqual(listener.dropped, 469)

    async def test_live_policy_is_persisted_and_invalid_changes_are_atomic(self):
        self.gateway.configure({'max_connections':512, 'memory_reserve_mb':128})
        before = dict(self.gateway.policy)
        for value in ({'max_udp_associations':1000}, {'command':'id'}, {'probe_interval':float('nan')}):
            with self.assertRaises(ValueError):self.gateway.configure(value)
        self.assertEqual(self.gateway.policy, before)
        self.assertEqual(Gateway(self.config, self.store).policy, before)


class PlanTests(unittest.TestCase):
    def test_udp_plan_supports_all_carriers_with_data_only_reconstruction(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            services = [{'id':'wg','listen':'0.0.0.0:51820','target':'127.0.0.1:51821','protocol':'udp'},
                        {'id':'web','listen':'0.0.0.0:443','target':'127.0.0.1:8443'}]
            spec = {'iran':'192.0.2.10','foreign':'198.51.100.20','services':services,
                    'transports':list(TRANSPORTS),'experimental':True,'open_ufw':False}
            summary = make_plan(root/'plan',spec['iran'],spec['foreign'],services,list(TRANSPORTS),'fixture-password-123',True)
            iran, foreign = load_config(root/'plan/iran/node.json'), load_config(root/'plan/foreign/node.json')
            self.assertEqual(summary['services'], services)
            self.assertIn(51820, summary['firewall']['iran']['udp'])
            self.assertNotIn(51820, summary['firewall']['iran']['tcp'])
            self.assertNotIn('wg', foreign['targets'])
            self.assertEqual(foreign['udp_relays']['wg']['target'], '127.0.0.1:51821')
            self.assertTrue(next(p for p in iran['paths'] if p['id']=='paqet')['udp_backends']['wg'])
            for path in iran['paths']:self.assertIn('wg', path['backends'])
            manifest=json.loads((root/'plan/foreign/install.json').read_text());manifest['open_ufw']=False
            atomic_json(root/'plan/foreign/install.json', manifest)
            validated_node(root, spec, node_files(root/'plan/foreign'))

    def test_tcp_and_udp_can_share_the_public_port_and_udp_conflicts_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            services=[{'id':'tcp','listen':'0.0.0.0:443','target':'127.0.0.1:8443'},
                      {'id':'udp','listen':'0.0.0.0:443','target':'127.0.0.1:8443','protocol':'udp'}]
            make_plan(Path(temp)/'good','192.0.2.10','198.51.100.20',services,['frp-wss'],'fixture-password-123')
            services.append({**services[-1], 'id':'duplicate'})
            with self.assertRaises(ValueError):make_plan(Path(temp)/'bad','192.0.2.10','198.51.100.20',services,['frp-wss'],'fixture-password-123')
