"""Authenticated fresh end-to-end probes, carried by the same tunnel as data."""
import asyncio
import contextlib
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path
from .config import endpoint


def mac(key, body):
    return hmac.new(bytes.fromhex(key), body.encode(), hashlib.sha256).hexdigest()


def host_stats():
    result = {"time": time.time(), "load": list(os.getloadavg()), "pid": os.getpid()}
    try:
        mem = {}
        with open("/proc/meminfo") as f:
            for line in f:
                k,v = line.split(":", 1)
                mem[k] = int(v.strip().split()[0]) * 1024
        result["memory_total"] = mem["MemTotal"]
        result["memory_used"] = mem["MemTotal"] - mem["MemAvailable"]
        result["memory_available"] = mem["MemAvailable"]
        # Respect a container/VPS cgroup limit when it is lower than host RAM.
        limit_path = Path('/sys/fs/cgroup/memory.max')
        if limit_path.exists():
            limit = limit_path.read_text().strip()
            current = Path('/sys/fs/cgroup/memory.current').read_text().strip()
            if limit.isdigit() and current.isdigit() and 0 < int(limit) < result['memory_total']:
                result['memory_total'] = int(limit)
                result['memory_used'] = min(int(current), int(limit))
                result['memory_available'] = max(0, int(limit) - int(current))
    except (OSError, KeyError):
        pass
    return result


async def target_status(target):
    stream = None
    try:
        _,stream = await asyncio.wait_for(asyncio.open_connection(*endpoint(target)),0.5)
        return True
    except (OSError,asyncio.TimeoutError):
        return False
    finally:
        if stream:
            stream.close()
            with contextlib.suppress(OSError):await stream.wait_closed()


async def responder(reader, writer, key, targets=None):
    try:
        raw = await asyncio.wait_for(reader.readline(), 3)
        if len(raw) > 4096:
            return
        request = json.loads(raw)
        nonce = request["nonce"]
        if not isinstance(nonce, str) or len(nonce) != 64:
            return
        if not hmac.compare_digest(mac(key, "probe:" + nonce), request.get("auth", "")):
            return
        stats = host_stats()
        if targets:
            results = await asyncio.gather(*(target_status(t) for t in targets.values()))
            stats['services'] = dict(zip(targets,results))
        body = json.dumps({"nonce": nonce, "stats": stats}, sort_keys=True, separators=(",", ":"))
        writer.write((json.dumps({"body": body, "auth": mac(key, body)}) + "\n").encode())
        await writer.drain()
    except (OSError, ValueError, KeyError, TypeError, asyncio.TimeoutError):
        pass
    finally:
        writer.close()
        await writer.wait_closed()


async def start_responder(listen, key, targets=None):
    host,port = endpoint(listen)
    return await asyncio.start_server(lambda r,w: responder(r,w,key,targets), host, port, limit=8192)


async def probe(address, key, timeout):
    writer = None
    start = time.monotonic()
    async def exchange():
        nonlocal writer
        reader,writer = await asyncio.open_connection(*endpoint(address), limit=8192)
        nonce = secrets.token_hex(32)
        writer.write((json.dumps({"nonce": nonce, "auth": mac(key, "probe:" + nonce)}) + "\n").encode())
        await writer.drain()
        packet = json.loads(await reader.readline())
        if not hmac.compare_digest(mac(key, packet["body"]), packet["auth"]):
            raise ValueError("health signature mismatch")
        body = json.loads(packet["body"])
        if body["nonce"] != nonce:
            raise ValueError("stale health response")
        return (time.monotonic()-start)*1000, body["stats"]
    try:
        # One deadline covers connect, write and authenticated response on 3.10+.
        return await asyncio.wait_for(exchange(),timeout)
    finally:
        if writer:
            writer.close()
            await writer.wait_closed()
