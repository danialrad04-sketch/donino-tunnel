from .runtime import continuum_status
import asyncio
import contextlib
import time
from collections import deque
from dataclasses import dataclass, field
from .config import endpoint
from .health import probe, host_stats
from .adaptive import Quality, AdaptiveRouter


@dataclass
class PathState:
    config: dict
    mode: str = "enabled"
    healthy: bool = False
    successes: int = 0
    failures: int = 0
    latency_ms: float | None = None
    error: str = "awaiting probe"
    remote: dict = field(default_factory=dict)
    active: int = 0
    bytes_up: int = 0
    bytes_down: int = 0
    history: deque = field(default_factory=lambda: deque(maxlen=120))
    quality: Quality = field(default_factory=Quality)

    def snapshot(self):
        return dict(id=self.config["id"], transport=self.config.get("transport", "external"),
                    priority=self.config.get("priority",100), mode=self.mode, healthy=self.healthy,
                    successes=self.successes, failures=self.failures, latency_ms=self.latency_ms,
                    error=self.error, remote=self.remote, active=self.active,
                    bytes_up=self.bytes_up, bytes_down=self.bytes_down, history=list(self.history))


class Gateway:
    def __init__(self, config, store):
        self.config, self.store = config, store
        self.paths = {p["id"]: PathState(p, mode=store.get("mode:"+p["id"], "enabled")) for p in config["paths"]}
        self.paused = store.get("paused", False)
        self.preferred = store.get("preferred")
        self.servers, self.tasks, self.connections = [], [], set()
        self.active, self.accepted, self.rejected, self.failovers = 0, 0, 0, 0
        self.started = time.time()
        self.last_path = None
        self.policy = config["policy"]
        self.adaptive = store.get('adaptive',False) is True
        self.router = AdaptiveRouter(self.policy)

    def candidates(self, service=None):
        paths = [p for p in self.paths.values() if p.mode == "enabled" and p.healthy and
                 (service is None or p.remote.get('services',{}).get(service,True))]
        if self.adaptive:return self.router.rank(paths,service,self.preferred)
        return sorted(paths, key=lambda p: (p.config["id"] != self.preferred,
                      p.config.get("priority",100), (p.latency_ms or 0) + p.active*0.2))

    def action(self, path_id, action):
        if action in ('adaptive','static') and path_id is None:
            self.adaptive=action=='adaptive';self.store.set('adaptive',self.adaptive)
            self.router.leaders.clear()
        elif action in ("pause", "resume") and path_id is None:
            self.paused = action == "pause"
            self.store.set("paused", self.paused)
        elif action == "auto" and path_id is None:
            self.preferred = None
            self.store.set("preferred", None)
        elif path_id in self.paths and action in ("enable", "disable", "drain", "prefer"):
            path = self.paths[path_id]
            if action == "prefer":
                if path.mode != "enabled":
                    raise ValueError("enable the path before preferring it")
                self.preferred = path_id
                self.store.set("preferred", path_id)
            else:
                path.mode = {"enable":"enabled", "disable":"disabled", "drain":"draining"}[action]
                self.store.set("mode:"+path_id, path.mode)
        else:
            raise ValueError("invalid path action")
        self.store.event("operator", {"path":path_id, "action":action})

    async def check(self, path):
        before = path.healthy
        try:
            latency,remote = await probe(path.config["health"],self.config["health_key"],self.policy["probe_timeout"])
            path.quality.probe(latency,time.monotonic())
            path.latency_ms = latency if path.latency_ms is None else 0.3*latency + 0.7*path.latency_ms
            path.remote = remote
            path.successes += 1
            path.failures = 0
            path.error = ""
            if path.successes >= self.policy["recoveries"]:
                path.healthy = True
            path.history.append({"time":time.time(), "latency":round(latency,2), "ok":True})
        except (OSError, ValueError, KeyError, TypeError, asyncio.TimeoutError) as e:
            path.quality.probe(None,time.monotonic())
            path.failures += 1
            path.successes = 0
            path.error = type(e).__name__
            if path.failures >= self.policy["failures"]:
                path.healthy = False
            path.history.append({"time":time.time(), "latency":None, "ok":False})
        if before != path.healthy:
            self.store.event("path-health", {"path":path.config["id"], "healthy":path.healthy})

    async def monitor(self):
        while True:
            await asyncio.gather(*(self.check(p) for p in self.paths.values()))
            await asyncio.sleep(self.policy["probe_interval"])

    async def start(self):
        # Start all listeners transactionally: no partial startup on a port conflict.
        try:
            for service in self.config["services"]:
                server = await asyncio.start_server(lambda r,w,s=service: self.handle(r,w,s),
                                                     *endpoint(service["listen"]))
                self.servers.append(server)
        except BaseException:
            await self.stop()
            raise
        self.tasks.append(asyncio.create_task(self.monitor()))

    async def stop(self):
        for server in self.servers:
            server.close()
        await asyncio.gather(*(s.wait_closed() for s in self.servers))
        tasks = self.tasks + list(self.connections)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self.tasks.clear()
        self.servers.clear()

    async def handle(self, reader, writer, service):
        task = asyncio.current_task()
        self.connections.add(task)
        upstream = None
        chosen = None
        counted = False
        pumps = []
        try:
            if self.paused or self.active >= self.policy["max_connections"]:
                self.rejected += 1
                return
            self.active += 1
            counted = True
            for path in self.candidates(service['id']):
                try:
                    upstream_reader, upstream = await asyncio.wait_for(
                        asyncio.open_connection(*endpoint(path.config["backends"][service["id"]])),
                        self.policy["connect_timeout"])
                    chosen = path
                    break
                except (OSError, asyncio.TimeoutError):
                    # Only retry before consuming or forwarding any client byte.
                    path.healthy = False
                    path.successes = 0
                    path.error = "backend-connect-failed"
                    path.quality.probe(None,time.monotonic())
                    self.store.event("backend-connect-failed", {"path":path.config["id"], "service":service["id"]})
            if chosen is None:
                self.rejected += 1
                return
            self.accepted += 1
            chosen.active += 1
            self.router.selected(service['id'],chosen)
            name = chosen.config["id"]
            if self.last_path and self.last_path != name:
                self.failovers += 1
                self.store.event("route-change", {"from":self.last_path,"to":name})
            self.last_path = name
            activity = [time.monotonic()]

            async def copy(source, destination, direction):
                while chunk := await source.read(65536):
                    activity[0] = time.monotonic()
                    destination.write(chunk)
                    drained_at=time.monotonic()
                    await destination.drain()
                    if direction=='up':chosen.quality.drain(time.monotonic()-drained_at,time.monotonic())
                    if direction == "up":
                        chosen.bytes_up += len(chunk)
                    else:
                        chosen.bytes_down += len(chunk)
                if destination.can_write_eof():
                    destination.write_eof()
                    await destination.drain()

            async def watchdog():
                while True:
                    await asyncio.sleep(min(5, self.policy["idle_timeout"]))
                    if time.monotonic()-activity[0] >= self.policy["idle_timeout"]:
                        raise TimeoutError("connection idle")

            pumps = [asyncio.create_task(copy(reader,upstream,"up")),
                     asyncio.create_task(copy(upstream_reader,writer,"down"))]
            guard = asyncio.create_task(watchdog())
            pumps.append(guard)
            # Half-close is preserved: wait for both copy tasks unless an error/idle timeout occurs.
            pending = set(pumps[:2])
            while pending:
                done,_ = await asyncio.wait(pending | {guard}, return_when=asyncio.FIRST_COMPLETED)
                for item in done:
                    item.result()
                pending -= done
        except (OSError, asyncio.TimeoutError):
            pass
        finally:
            for p in pumps:
                p.cancel()
            await asyncio.gather(*pumps, return_exceptions=True)
            for stream in [upstream,writer]:
                if stream:
                    stream.close()
                    with contextlib.suppress(OSError):
                        await stream.wait_closed()
            if chosen:
                chosen.active -= 1
            if counted:
                self.active -= 1
            self.connections.discard(task)

    def snapshot(self):
        service=self.config['services'][0]['id'] if self.config['services'] else None
        candidates=self.candidates(service)
        paths=[]
        for p in self.paths.values():
            row=p.snapshot();row['quality']=self.router.details(p)
            if p.config['id']=='donino-continuum':row['continuum']=continuum_status('iran')
            paths.append(row)
        return {"version":"0.1.0", "role":"iran","bootstrap":self.config.get('bootstrap',False),"public_address":self.config.get('public_address'), "time":time.time(), "uptime":time.time()-self.started,
                "paused":self.paused, "preferred":self.preferred, "active":self.active,
                "accepted":self.accepted, "rejected":self.rejected,"route_changes":self.failovers,
                "selected":candidates[0].config["id"] if candidates else None,
                "routing_strategy":'adaptive' if self.adaptive else 'static',
                "host":host_stats(), "paths":paths,
                "services":self.config["services"], "events":self.store.events()}
