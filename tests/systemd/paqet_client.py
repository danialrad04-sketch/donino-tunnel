"""Actual Paqet native TCP, UDP and authenticated SOCKS5 fixture, run on Iran."""
import concurrent.futures
import hashlib
import json
import os
import socket
import struct


def receive(conn,n):
    data=bytearray()
    while len(data)<n:
        block=conn.recv(n-len(data))
        if not block:raise AssertionError('unexpected TCP EOF')
        data.extend(block)
    return bytes(data)


def tcp_test(conn):
    conn.settimeout(20)
    payload=os.urandom(256*1024);conn.sendall(payload)
    assert hashlib.sha256(receive(conn,len(payload))).digest()==hashlib.sha256(payload).digest()
    return len(payload)


def udp_test(index):
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as conn:
        conn.settimeout(20);conn.connect(('127.0.0.1',444))
        # Back-to-back datagrams of distinct lengths must not merge or split.
        blocks=[struct.pack('!II',index,n)+os.urandom(size) for n,size in enumerate([32,512,1399,4088]*4)]
        for block in blocks:conn.send(block)
        received=[conn.recv(65535) for _ in blocks]
        assert sorted(received)==sorted(blocks),'UDP boundaries or source isolation failed'
        conn.settimeout(.3);conn.send(os.urandom(4097))
        try:conn.recv(65535)
        except socket.timeout:pass
        else:raise AssertionError('upstream oversized-datagram limit changed')
        return sum(map(len,blocks))


def socks_command(command,password=b'fixture-socks-password'):
    conn=socket.create_connection(('127.0.0.1',1080),timeout=20);conn.settimeout(20)
    conn.sendall(b'\x05\x01\x02');assert receive(conn,2)==b'\x05\x02'
    user=b'fixture';conn.sendall(b'\x01'+bytes([len(user)])+user+bytes([len(password)])+password)
    reply=receive(conn,2)
    if password!=b'fixture-socks-password':
        assert reply!=b'\x01\x00';conn.close();return
    assert reply==b'\x01\x00'
    target=b'\x00\x00\x00\x00\x00\x00' if command==3 else socket.inet_aton('127.0.0.1')+struct.pack('!H',18083)
    conn.sendall(bytes([5,command,0,1])+target)
    head=receive(conn,4);assert head[:3]==b'\x05\x00\x00'
    assert head[3]==1,'fixture expects IPv4 SOCKS bind reply'
    addr=socket.inet_ntoa(receive(conn,4));port=struct.unpack('!H',receive(conn,2))[0]
    return conn,(addr,port)


def main():
    with socket.create_connection(('127.0.0.1',444),timeout=20) as conn:tcp_bytes=tcp_test(conn)
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:udp_bytes=list(pool.map(udp_test,range(8)))
    socks_command(1,b'wrong-password')
    control,_=socks_command(1)
    with control:socks_tcp=tcp_test(control)
    control,relay=socks_command(3)
    with control,socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
        udp.settimeout(20);udp.connect(relay)
        header=b'\x00\x00\x00\x01'+socket.inet_aton('127.0.0.1')+struct.pack('!H',18082)
        blocks=[header+os.urandom(size) for size in [32,512,1399,4096]*4]
        for block in blocks:udp.send(block)
        assert sorted(udp.recv(65535) for _ in blocks)==sorted(blocks),'SOCKS UDP framing changed'
    print(json.dumps({'native_tcp_bytes_each_direction':tcp_bytes,'native_udp_clients':8,'native_udp_datagrams_per_client':16,
                      'native_udp_bytes_each_direction':sum(udp_bytes),'udp_boundaries_and_source_isolation':True,'native_udp_max_payload_tested':4096,'oversized_datagram_rejected':True,
                      'socks5_authenticated_tcp_bytes_each_direction':socks_tcp,'socks5_wrong_password_rejected':True,
                      'socks5_udp_associate_datagrams':16,'socks5_udp_boundaries':True}))

if __name__=='__main__':main()
