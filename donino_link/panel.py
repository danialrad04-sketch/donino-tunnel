import asyncio
import hashlib
import hmac
import json
import secrets
import ssl
import time
from collections import OrderedDict, deque
from pathlib import Path
from aiohttp import web, ClientSession, ClientTimeout, UnixConnector, ClientError
from .config import endpoint

AUTH = web.RequestKey("auth", object)


def password_record(password):
    if len(password) < 12 or len(password) > 256:
        raise ValueError("password needs 12 to 256 characters")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=32768, r=8, p=1, maxmem=64*1024*1024)
    return {"salt":salt.hex(),"digest":digest.hex()}


def verify_password(password, record):
    if not isinstance(password,str) or len(password) > 256:
        return False
    digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(record["salt"]), n=32768, r=8, p=1, maxmem=64*1024*1024)
    return hmac.compare_digest(digest.hex(),record["digest"])


class Panel:
    def __init__(self, gateway):
        self.gateway = gateway
        self.config = gateway.config["panel"]
        self.record = json.loads(Path(self.config["credentials_file"]).read_text())
        self.api_digest = hashlib.sha256(Path(self.config["api_token_file"]).read_text().strip().encode()).digest()
        self.sessions = OrderedDict()
        self.attempts = OrderedDict()
        self.login_lock = asyncio.Lock()
        self.runner = None
        self.app = web.Application(client_max_size=16384, middlewares=[self.security,self.authentication])
        self.app.add_routes([
            web.get("/",self.index),web.get("/app.js",self.static),web.get("/style.css",self.static),web.get('/Vazirmatn.woff2',self.static),
            web.get("/healthz",self.healthz),web.post("/api/login",self.login),
            web.post("/api/logout",self.logout),web.get("/api/session",self.session),
            web.get("/api/status",self.status),web.get("/api/metrics",self.metrics),
            web.post("/api/action",self.action),web.get("/api/export",self.export),
            web.get('/api/provision/state',self.provision),
            web.post('/api/provision/profiles',self.provision),
            web.post('/api/provision/preview',self.provision),
            web.post('/api/provision/start',self.provision),
        ])

    @web.middleware
    async def security(self, request, handler):
        try:
            response = await handler(request)
        except web.HTTPException as e:
            self.headers(request,e)
            raise
        self.headers(request,response)
        return response

    def headers(self, request, response):
        response.headers.update({
            "X-Content-Type-Options":"nosniff","X-Frame-Options":"DENY",
            "Referrer-Policy":"no-referrer","Cache-Control":"no-store",
            "Content-Security-Policy":"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
            "Permissions-Policy":"camera=(), microphone=(), geolocation=()",
        })
        if request.secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"

    def check_origin(self, request):
        origin = request.headers.get("Origin")
        if origin and origin != f"{request.scheme}://{request.host}":
            raise web.HTTPForbidden(text="origin rejected")
        if request.headers.get("Sec-Fetch-Site") == "cross-site":
            raise web.HTTPForbidden(text="cross-site request rejected")

    @web.middleware
    async def authentication(self, request, handler):
        path = request.path
        if path == "/api/login":
            self.check_origin(request)
        if path.startswith("/api/") and path != "/api/login":
            bearer = request.headers.get("Authorization","")
            if bearer.startswith("Bearer ") and hmac.compare_digest(
                hashlib.sha256(bearer[7:].encode()).digest(),self.api_digest):
                request[AUTH] = "bearer"
            else:
                token = request.cookies.get("donino_session","")
                key = hashlib.sha256(token.encode()).hexdigest()
                current = self.sessions.get(key)
                if not current or current["expires"] < time.monotonic():
                    self.sessions.pop(key,None)
                    raise web.HTTPUnauthorized(text="authentication required")
                request[AUTH] = current
                self.check_origin(request)
                if request.method not in ("GET","HEAD") and not hmac.compare_digest(
                    request.headers.get("X-CSRF-Token",""),current["csrf"]):
                    raise web.HTTPForbidden(text="CSRF token required")
        return await handler(request)

    async def index(self, request):
        return web.FileResponse(Path(__file__).parent / "web" / "index.html")

    async def static(self, request):
        return web.FileResponse(Path(__file__).parent / "web" / request.path.lstrip("/"))

    async def healthz(self, request):
        # Liveness only; no infrastructure details without authentication.
        return web.json_response({"alive":True})

    async def login(self, request):
        peer = request.remote or "unknown"
        now = time.monotonic()
        attempts = self.attempts.setdefault(peer,deque(maxlen=10))
        self.attempts.move_to_end(peer)
        while len(self.attempts) > 1024:
            self.attempts.popitem(last=False)
        while attempts and now-attempts[0] > 300:
            attempts.popleft()
        if len(attempts) >= 5:
            raise web.HTTPTooManyRequests(text="wait before retrying",headers={"Retry-After":"300"})
        attempts.append(now)
        try:
            body = await request.json()
            password = body.get("password","")
        except (ValueError,AttributeError):
            raise web.HTTPBadRequest(text="invalid JSON")
        # Serialize password checks to bound scrypt memory even across many IPs.
        async with self.login_lock:
            valid = await asyncio.to_thread(verify_password,password,self.record)
        if not valid:
            self.gateway.store.event("login-failed",{})
            raise web.HTTPUnauthorized(text="invalid password")
        attempts.clear()
        token = secrets.token_urlsafe(32)
        key = hashlib.sha256(token.encode()).hexdigest()
        csrf = secrets.token_urlsafe(32)
        self.sessions[key] = {"csrf":csrf,"expires":time.monotonic()+3600*8}
        while len(self.sessions) > 128:
            self.sessions.popitem(last=False)
        response = web.json_response({"csrf":csrf})
        response.set_cookie("donino_session",token,httponly=True,secure=request.secure,samesite="Strict",max_age=3600*8,path="/")
        self.gateway.store.event("login",{})
        return response

    async def logout(self, request):
        token = request.cookies.get("donino_session","")
        self.sessions.pop(hashlib.sha256(token.encode()).hexdigest(),None)
        result = web.json_response({"ok":True})
        result.del_cookie("donino_session",path="/")
        return result

    async def session(self, request):
        auth = request[AUTH]
        return web.json_response({"csrf":auth["csrf"] if isinstance(auth,dict) else None})

    async def status(self, request):
        return web.json_response(self.gateway.snapshot())

    async def action(self, request):
        try:
            body = await request.json()
            self.gateway.action(body.get("path"),body["action"])
        except (ValueError,KeyError,TypeError,AttributeError):
            raise web.HTTPBadRequest(text="invalid action")
        return web.json_response({"ok":True})

    async def provision(self, request):
        # Fixed local endpoint. Public requests cannot choose socket, command,
        # identity path, remote script, download URL or arbitrary worker route.
        from .provision import SOCKET
        route = request.path.removeprefix('/api/provision')
        if not SOCKET.exists():
            if request.method == 'GET':
                return web.json_response({'available':False,'reason':'سرویس نصب خودکار روی ایران هنوز فعال نشده است.'})
            return web.json_response({'error':'سرویس نصب خودکار در دسترس نیست.'},status=503)
        try:
            body = await request.json() if request.method == 'POST' else None
            if body is not None and not isinstance(body,dict):
                raise web.HTTPBadRequest(text='invalid JSON')
            async with ClientSession(connector=UnixConnector(path=str(SOCKET)),timeout=ClientTimeout(total=90)) as session:
                async with session.request(request.method,'http://localhost'+route,json=body) as response:
                    result = await response.json()
                    if request.method == 'POST' and response.status < 400:
                        self.gateway.store.event('provision',{'operation':route,'id':result.get('id')})
                    return web.json_response(result,status=response.status)
        except (ClientError,asyncio.TimeoutError,OSError):
            return web.json_response({'error':'ارتباط با سرویس نصب قطع شد؛ وضعیت عملیات را دوباره بررسی کن.'},status=503)
        except ValueError:
            raise web.HTTPBadRequest(text='invalid JSON')

    async def export(self, request):
        # Observations only, deliberately excludes tokens and configuration secrets.
        return web.json_response(self.gateway.snapshot(),headers={"Content-Disposition":"attachment; filename=donino-link-observations.json"})

    async def metrics(self, request):
        g = self.gateway
        lines = ["# TYPE donino_active_connections gauge",f"donino_active_connections {g.active}",
                 "# TYPE donino_accepted_total counter",f"donino_accepted_total {g.accepted}",
                 "# TYPE donino_rejected_total counter",f"donino_rejected_total {g.rejected}"]
        for p in g.paths.values():
            label = '{path="'+p.config["id"]+'"}'
            lines += [f"donino_path_healthy{label} {int(p.healthy)}",f"donino_path_latency_ms{label} {p.latency_ms or 0}",
                      f"donino_path_enabled{label} {int(p.mode=='enabled')}",
                      f"donino_bytes_up_total{label} {p.bytes_up}",f"donino_bytes_down_total{label} {p.bytes_down}"]
        return web.Response(text="\n".join(lines)+"\n",content_type="text/plain")

    async def start(self):
        self.runner = web.AppRunner(self.app,access_log=None)
        await self.runner.setup()
        tls = None
        if self.config.get("tls_cert"):
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.minimum_version = ssl.TLSVersion.TLSv1_2
            tls.load_cert_chain(self.config["tls_cert"],self.config["tls_key"])
        await web.TCPSite(self.runner,*endpoint(self.config["listen"]),ssl_context=tls).start()

    async def stop(self):
        if self.runner:
            await self.runner.cleanup()
