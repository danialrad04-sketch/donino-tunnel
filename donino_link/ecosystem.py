"""Independent, bounded API adapters. Vendor databases remain authoritative.

No vendor source is incorporated. Credentials live in a private sidecar, never
in observations, browser storage, event details or downloadable backups.
"""
import asyncio
import base64
import hashlib
import ipaddress
import json
import re
import secrets
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from urllib.parse import quote, urlsplit, urlunsplit

from aiohttp import ClientSession, ClientTimeout, CookieJar, DummyCookieJar, Fingerprint, ClientError, UnixConnector
from .config import atomic_json

KINDS = ('pasarguard', '3x-ui', '3x-ui-legacy')
MAX_BODY = 8 * 1024 * 1024
MAX_ROWS = 10000


class ProviderError(ValueError):
    pass


def fields(body, allowed, required=()):
    if not isinstance(body, dict) or set(body) - set(allowed) or set(required) - set(body):
        raise ValueError('فیلدهای درخواست معتبر نیستند.')


def text(value, maximum=128, empty=False):
    if not isinstance(value, str) or len(value) > maximum or (not value and not empty) or any(ord(c) < 32 for c in value):
        raise ValueError('مقدار متنی معتبر نیست.')
    return value


def number(value, high=2**53-1):
    if type(value) is not int or not 0 <= value <= high:
        raise ValueError('عدد باید صحیح، مثبت یا صفر و در محدودهٔ مجاز باشد.')
    return value


def base_url(value):
    text(value, 1024)
    u = urlsplit(value)
    if u.username or u.password or u.query or u.fragment or not u.hostname or u.scheme not in ('https', 'http'):
        raise ValueError('آدرس پایهٔ پنل باید HTTPS و بدون رمز، query یا fragment باشد.')
    try:
        address = ipaddress.ip_address(u.hostname)
    except ValueError:
        address = None
    if address and (address.is_link_local or address.is_unspecified or address.is_multicast):
        raise ValueError('آدرس مقصد مجاز نیست.')
    if u.hostname.lower() in ('metadata.google.internal', 'metadata', 'instance-data'):
        raise ValueError('آدرس مقصد مجاز نیست.')
    if u.scheme == 'http' and not (address and address.is_loopback):
        raise ValueError('HTTP فقط برای IP محلی loopback مجاز است؛ برای سرور دیگر HTTPS لازم است.')
    try:
        u.port
    except ValueError:
        raise ValueError('پورت معتبر نیست.') from None
    if re.search(r'[%\\\s]', value) or any(p in ('.', '..') for p in u.path.split('/')):
        raise ValueError('مسیر پایه معتبر نیست.')
    return value.rstrip('/')


def epoch(value):
    if not value:
        return 0
    if isinstance(value, str):
        return int(datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp())
    return int(value)


def revision(raw):
    return hashlib.sha256(json.dumps(raw, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def identity(value):
    # URL path segments cannot choose a different upstream route.
    return quote(text(value, 256), safe='')


def modern_client(record):
    client = {k: v for k, v in record.items() if k not in ('traffic', 'inboundIds')}
    # The v3 read model uses numeric database id + uuid; its write model uses
    # id for the credential UUID. Sending the read model back corrupts identity.
    if 'uuid' in client:
        client['id'] = client.pop('uuid')
    if isinstance(client.get('allowedIPs'), str):
        client['allowedIPs'] = [v for v in re.split(r'[,\s]+', client['allowedIPs']) if v]
    return client


def delivery_links(links, host, port=None):
    host = text(host, 253)
    try:
        address = ipaddress.ip_address(host)
        target = '['+host+']' if address.version == 6 else host
    except ValueError:
        if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', host):
            raise ValueError('آدرس عمومی باید IP یا دامنه، بدون scheme و پورت باشد.')
        target = host
    if port is not None:
        number(port, 65535)
        if port == 0: raise ValueError('پورت عمومی معتبر نیست.')
    parsed, ports = [], set()
    for link in links:
        if link.startswith('vmess://'):
            try:
                raw = link[8:];profile = json.loads(base64.b64decode(raw + '='*((-len(raw))%4), validate=True))
                ports.add(int(profile['port']));parsed.append(('vmess', profile))
            except (ValueError, KeyError, TypeError):
                raise ValueError('ساختار لینک VMess برای نگاشت مقصد معتبر نیست.') from None
        else:
            u = urlsplit(link)
            if u.scheme not in ('vless', 'trojan') or '@' not in u.netloc or not u.port:
                raise ValueError('نگاشت مقصد در این نسخه فقط برای VLESS، VMess و Trojan پشتیبانی می‌شود.')
            ports.add(u.port);parsed.append(('uri', u))
    if port is not None and len(ports) > 1:
        raise ValueError('این کاربر چند پورت مقصد دارد؛ پورت عمومی را خالی بگذار یا نگاشت‌ها را در پنل مقصد تنظیم کن.')
    result = []
    for kind, profile in parsed:
        if kind == 'vmess':
            profile['add'] = host
            if port is not None: profile['port'] = str(port)
            result.append('vmess://'+base64.b64encode(json.dumps(profile, separators=(',', ':')).encode()).decode())
        else:
            netloc = profile.netloc.rsplit('@', 1)[0]+'@'+target+':'+str(port or profile.port)
            result.append(urlunsplit((profile.scheme, netloc, profile.path, profile.query, profile.fragment)))
    return result


class Upstream:
    def __init__(self, config, session):
        self.config, self.session = config, session

    async def call(self, method, route, *, data=None, payload=None):
        if self.config.get('peer_profile'):
            from .provision import SOCKET
            try:
                async with ClientSession(connector=UnixConnector(path=str(SOCKET)), timeout=ClientTimeout(total=35)) as bridge:
                    async with bridge.post('http://localhost/vpn-backend-api', json={'profile_id': self.config['peer_profile'],
                        'request': {'method':method,'route':route,'data':data,'payload':payload}}) as response:
                        chunks, size = [], 0
                        async for chunk in response.content.iter_chunked(65536):
                            size += len(chunk)
                            if size > MAX_BODY: raise ProviderError('پاسخ backend از سقف مجاز بیشتر است.')
                            chunks.append(chunk)
                        result = json.loads(b''.join(chunks))
                        if response.status != 200 or not isinstance(result,dict) or result.get('success') is not True:
                            raise ProviderError('عملیات backend خارج پذیرفته نشد؛ جفت‌سازی، نسخهٔ عامل و وضعیت backend را بررسی کن.')
                        return result.get('obj')
            except (ClientError, asyncio.TimeoutError, OSError, json.JSONDecodeError):
                raise ProviderError('کانال امن backend خارج در دسترس نیست؛ نوشتن خودکار تکرار نمی‌شود.') from None
        ssl = Fingerprint(bytes.fromhex(self.config['fingerprint'])) if self.config.get('fingerprint') else True
        headers = {'Authorization': ('ApiKey ' if self.config.get('auth') == 'apikey' else 'Bearer ') + self.config['token']} if self.config.get('token') else {}
        try:
            async with self.session.request(method, self.config['url'] + route, headers=headers,
                                            data=data, json=payload, ssl=ssl, allow_redirects=False) as response:
                if response.status != 200 and response.status != 201:
                    # Do not return server messages: they can contain credentials or HTML.
                    raise ProviderError('پنل مقصد پاسخ HTTP %s داد؛ مجوز و نسخهٔ API را بررسی کن.' % response.status)
                chunks, length = [], 0
                async for chunk in response.content.iter_chunked(65536):
                    length += len(chunk)
                    if length > MAX_BODY:
                        raise ProviderError('پاسخ پنل از سقف ۸ مگابایت بیشتر است.')
                    chunks.append(chunk)
                result = json.loads(b''.join(chunks))
                if self.config['kind'].startswith('3x-ui'):
                    if not isinstance(result, dict) or result.get('success') is not True:
                        raise ProviderError('عملیات توسط 3x-ui پذیرفته نشد؛ وضعیت مقصد را بررسی کن.')
                    return result.get('obj')
                return result
        except (ClientError, asyncio.TimeoutError, OSError):
            raise ProviderError('اتصال امن به پنل برقرار نشد یا مهلت پاسخ پایان یافت. عملیات نوشتن خودکار تکرار نمی‌شود؛ وضعیت مقصد را بررسی کن.') from None
        except (json.JSONDecodeError, UnicodeError):
            raise ProviderError('پاسخ JSON معتبر از API مقصد دریافت نشد.') from None


class Ecosystem:
    def __init__(self, store, path):
        self.store, self.path = store, Path(path)
        self.lock = asyncio.Lock()
        self.writes = asyncio.Lock()
        self.reads = asyncio.Semaphore(4)
        self.connections = json.loads(self.path.read_text()) if self.path.exists() else []
        if self.path.exists():
            self.path.chmod(0o600)

    def public(self, config):
        result = {k: config[k] for k in ('id', 'name', 'kind', 'url', 'writable', 'fingerprint')}
        result['peer_profile'] = config.get('peer_profile')
        return result

    def state(self):
        return {'connections': [self.public(c) for c in self.connections], 'catalog': catalog()}

    def find(self, provider):
        result = next((c for c in self.connections if c['id'] == provider), None)
        if result is None:
            raise ValueError('اتصال پنل پیدا نشد.')
        return result

    @asynccontextmanager
    async def upstream(self, config):
        jar = CookieJar(unsafe=True) if config['kind'] == '3x-ui-legacy' else DummyCookieJar()
        async with ClientSession(timeout=ClientTimeout(total=15, connect=5), cookie_jar=jar,
                                 trust_env=False) as session:
            upstream = Upstream(config, session)
            if config['kind'] == '3x-ui-legacy':
                await upstream.call('POST', '/login', data={'username': config['username'], 'password': config['password']})
            yield upstream

    async def connect(self, body, peer_profile=None):
        fields(body, ('name', 'kind', 'url', 'token', 'username', 'password', 'writable', 'fingerprint', 'auth'), ('name', 'kind', 'url'))
        if body['kind'] not in KINDS or type(body.get('writable', False)) is not bool:
            raise ValueError('نوع اتصال یا مجوز نوشتن معتبر نیست.')
        if body.get('auth', 'bearer') not in ('bearer', 'apikey'):
            raise ValueError('نوع توکن معتبر نیست.')
        config = {'auth': body.get('auth', 'bearer'), 'id': uuid.uuid4().hex, 'name': text(body['name'], 64), 'kind': body['kind'],
                  'url': base_url(body['url']), 'writable': body.get('writable', False),
                  'fingerprint': body.get('fingerprint', '')}
        if config['fingerprint'] and not re.fullmatch(r'[a-fA-F0-9]{64}', config['fingerprint']):
            raise ValueError('اثر انگشت گواهی باید SHA256 با ۶۴ رقم hex باشد.')
        if peer_profile:
            if config['kind'] != '3x-ui' or not re.fullmatch(r'[a-f0-9]{32}', peer_profile):
                raise ValueError('Invalid internal peer profile')
            config['peer_profile'] = peer_profile
        elif config['kind'] == '3x-ui-legacy':
            config.update(username=text(body.get('username'), 128), password=text(body.get('password'), 256))
        else:
            config['token'] = text(body.get('token'), 4096)
        async with self.lock:
            if len(self.connections) >= 16:
                raise ValueError('حداکثر ۱۶ پنل قابل ثبت است.')
            if any(c['url'] == config['url'] for c in self.connections):
                raise ValueError('این آدرس قبلاً ثبت شده است؛ ابتدا اتصال قبلی را حذف کن.')
            # Verify the selected API contract before persisting credentials.
            async with self.reads:
                async with self.upstream(config) as upstream:
                    await self.fetch(upstream, offset=0, limit=1)
            updated = self.connections + [config]
            atomic_json(self.path, updated)
            self.connections = updated
            self.store.event('ecosystem-connect', {'provider': config['id'], 'kind': config['kind']})
        return self.public(config)

    async def disconnect(self, provider):
        async with self.writes, self.lock:
            config = self.find(provider)
            updated = [c for c in self.connections if c is not config]
            atomic_json(self.path, updated)
            self.connections = updated
            self.store.event('ecosystem-disconnect', {'provider': provider})
        return {'ok': True}

    async def fetch(self, upstream, offset=0, limit=50, query=''):
        kind = upstream.config['kind']
        if kind == 'pasarguard':
            params = '?offset=%s&limit=%s' % (offset, limit)
            if query:
                params += '&username=' + quote(query, safe='')
            result = await upstream.call('GET', '/api/users' + params)
            if not isinstance(result, dict) or not isinstance(result.get('users'), list) or not isinstance(result.get('total'), int):
                raise ProviderError('ساختار API کاربران PasarGuard با این آداپتر سازگار نیست.')
            return [self.pasar_row(r) for r in result['users']], result['total']
        # 3x-ui has multiple incompatible paging dialects. Bound the full response,
        # page locally without guessing an upstream dialect. No automatic polling.
        route = '/panel/api/clients/list' if kind == '3x-ui' else '/panel/api/inbounds/list'
        result = await upstream.call('GET', route)
        if not isinstance(result, list) or len(result) > MAX_ROWS:
            raise ProviderError('ساختار فهرست 3x-ui معتبر نیست یا از سقف ۱۰۰۰۰ ردیف بیشتر است.')
        rows = []
        if kind == '3x-ui':
            rows = [self.xui_row(modern_client(r), r.get('traffic') or {}, r.get('inboundIds') or []) for r in result]
        else:
            for inbound in result:
                settings = json.loads(inbound.get('settings') or '{}')
                stats = {r['email']: r for r in inbound.get('clientStats') or []}
                for client in settings.get('clients') or []:
                    if len(rows) >= MAX_ROWS:
                        raise ProviderError('بیش از ۱۰۰۰۰ کاربر؛ اتصال را به پنل‌های کوچک‌تر تقسیم کن.')
                    row = self.xui_row(client, stats.get(client.get('email'), {}), [inbound['id']])
                    row['key'] = str(inbound['id']) + ':' + client.get('email', '')
                    row['protocol'] = inbound.get('protocol', '')
                    rows.append(row)
        rows = [r for r in rows if query.casefold() in r['username'].casefold()]
        return rows[offset:offset+limit], len(rows)

    @staticmethod
    def pasar_row(r):
        return {'key': r['username'], 'username': r['username'], 'status': r['status'],
                'used': int(r.get('used_traffic') or 0), 'limit': int(r.get('data_limit') or 0),
                'expires': epoch(r.get('expire')), 'note': r.get('note') or '', 'inbounds': [],
                'revision': revision({k: r.get(k) for k in ('status', 'data_limit', 'expire', 'note')}),
                'subscription': bool(r.get('subscription_url'))}

    @staticmethod
    def xui_row(r, traffic, inbounds):
        used = int(traffic.get('up') or 0) + int(traffic.get('down') or 0)
        limit, expires = int(r.get('totalGB') or 0), int(r.get('expiryTime') or 0)
        # Negative expiryTime means relative duration until first use; preserve it.
        status = 'disabled' if r.get('enable') is False else 'limited' if limit and used >= limit else 'expired' if 0 < expires < time.time()*1000 else 'active'
        return {'key': r['email'], 'username': r['email'], 'status': status, 'used': used, 'limit': limit,
                'expires': int(expires/1000), 'note': r.get('comment') or '', 'inbounds': inbounds,
                'revision': revision({k: r.get(k) for k in ('email', 'id', 'password', 'enable', 'totalGB', 'expiryTime', 'comment', 'flow', 'subId', 'limitIp', 'limitHwid')}), 'subscription': True}

    async def users(self, provider, *, offset=0, limit=50, query=''):
        config = self.find(provider)
        number(offset, 1000000); number(limit, 100)
        if limit < 1:
            raise ValueError('اندازهٔ صفحه معتبر نیست.')
        text(query, 128, empty=True)
        async with self.reads:
            async with self.upstream(config) as upstream:
                rows, total = await self.fetch(upstream, offset, limit, query)
        # Secrets are never included in ordinary responses.
        for row in rows:
            if config['kind'] == '3x-ui-legacy':
                row['subscription'] = False
        return {'users': rows, 'total': total, 'offset': offset, 'limit': limit,
                'provider': self.public(config), 'observed_at': time.time()}

    async def inventory(self, provider):
        config = self.find(provider)
        async with self.reads:
            async with self.upstream(config) as upstream:
                if config['kind'] == 'pasarguard':
                    inbounds = await upstream.call('GET', '/api/inbounds')
                    nodes = await upstream.call('GET', '/api/nodes?offset=0&limit=100')
                    return {'inbounds': [{'id': str(i), 'name': str(i), 'protocol': 'managed'} for i in inbounds],
                            'nodes': [{'id': r['id'], 'name': r['name'], 'status': r.get('status', 'unknown')}
                                      for r in nodes.get('nodes', [])]}
                rows = await upstream.call('GET', '/panel/api/inbounds/list')
                return {'inbounds': [{'id': str(r['id']), 'name': r.get('remark') or str(r['id']),
                                      'protocol': r.get('protocol', ''), 'port': r.get('port'), 'enabled': r.get('enable')}
                                     for r in rows], 'nodes': []}

    async def user(self, upstream, key):
        if upstream.config['kind'] == 'pasarguard':
            r = await upstream.call('GET', '/api/user/' + identity(key))
            return r, self.pasar_row(r)
        if upstream.config['kind'] == '3x-ui':
            r = await upstream.call('GET', '/panel/api/clients/get/' + identity(key))
            client = modern_client(r['client'])
            return client, self.xui_row(client, {}, r['inboundIds'])
        inbound_id, email = key.split(':', 1)
        number(int(inbound_id), 2**31-1)
        r = await upstream.call('GET', '/panel/api/inbounds/get/' + str(int(inbound_id)))
        c = next((c for c in json.loads(r['settings']).get('clients', []) if c.get('email') == email), None)
        if c is None:
            raise ValueError('کاربر در مقصد پیدا نشد.')
        return c, self.xui_row(c, {}, [int(inbound_id)])

    async def mutate(self, provider, body):
        fields(body, ('operation', 'key', 'revision', 'username', 'limit', 'expires', 'enabled', 'note', 'inbounds'), ('operation',))
        operation = body['operation']
        if operation not in ('create', 'update', 'reset'):
            raise ValueError('عملیات پشتیبانی نمی‌شود.')
        async with self.writes:
            config = self.find(provider)
            if not config['writable']:
                raise ValueError('این اتصال فقط مشاهده است؛ برای نوشتن با مجوز مدیریت دوباره ثبت کن.')
            async with self.upstream(config) as upstream:
                if operation == 'create':
                    username = text(body.get('username'), 64)
                    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.@-]{2,63}', username):
                        raise ValueError('نام کاربر باید ۳ تا ۶۴ حرف لاتین، عدد، نقطه، خط تیره یا @ باشد.')
                    raw, key = {}, username
                else:
                    key = text(body.get('key'), 256)
                    raw, row = await self.user(upstream, key)
                    if not secrets.compare_digest(text(body.get('revision'), 64), row['revision']):
                        raise ValueError('تنظیمات کاربر در مقصد تغییر کرده است؛ فهرست را تازه کن و دوباره بررسی کن.')
                kind = config['kind']
                if operation == 'reset':
                    route = ('/api/user/' + identity(key) + '/reset') if kind == 'pasarguard' else ('/panel/api/clients/resetTraffic/' + identity(key)) if kind == '3x-ui' else ('/panel/api/inbounds/%s/resetClientTraffic/%s' % (row['inbounds'][0], identity(raw['email'])))
                    await upstream.call('POST', route)
                else:
                    limit = number(body.get('limit', 0)) if operation == 'create' or 'limit' in body else None
                    expires = number(body.get('expires', 0), 4102444800) if operation == 'create' or 'expires' in body else None
                    if 'enabled' in body and type(body['enabled']) is not bool:
                        raise ValueError('وضعیت فعال‌سازی معتبر نیست.')
                    note = text(body.get('note', ''), 500, empty=True) if operation == 'create' or 'note' in body else None
                    if kind == 'pasarguard':
                        payload = {}
                        if limit is not None: payload['data_limit'] = limit
                        if expires is not None: payload['expire'] = expires or None
                        if note is not None: payload['note'] = note
                        if 'enabled' in body: payload['status'] = 'active' if body['enabled'] else 'disabled'
                        if operation == 'create':
                            if payload.get('status') == 'disabled':
                                raise ValueError('کاربر جدید PasarGuard باید فعال ساخته شود.')
                            payload['username'] = username
                            await upstream.call('POST', '/api/user', payload=payload)
                        else:
                            await upstream.call('PUT', '/api/user/' + identity(key), payload=payload)
                    else:
                        if operation == 'create':
                            inbounds = body.get('inbounds')
                            if not isinstance(inbounds, list) or not 1 <= len(inbounds) <= 16:
                                raise ValueError('حداقل یک inbound و حداکثر ۱۶ مورد انتخاب کن.')
                            inbounds = [number(i, 2**31-1) for i in inbounds]
                            # Single inbound avoids partially committed fan-out creates.
                            if len(inbounds) != 1:
                                raise ValueError('در این نسخه ایجاد کاربر روی یک inbound انجام می‌شود.')
                            inbound = await upstream.call('GET', '/panel/api/inbounds/get/' + str(inbounds[0]))
                            if inbound.get('protocol') not in ('vless', 'vmess', 'trojan'):
                                raise ValueError('ایجاد کاربر در این نسخه فقط روی VLESS، VMess و Trojan پشتیبانی می‌شود.')
                            raw = {'id': str(uuid.uuid4()), 'password': secrets.token_urlsafe(24), 'email': username,
                                   'enable': True, 'subId': secrets.token_urlsafe(16), 'flow': '', 'limitIp': 0}
                            if inbound['protocol'] == 'vmess': raw['security'] = 'auto'
                            stream = inbound.get('streamSettings') or {}
                            if isinstance(stream, str): stream = json.loads(stream)
                            if inbound['protocol'] == 'vless' and stream.get('security') == 'reality' and stream.get('network') in ('tcp', 'raw'):
                                raw['flow'] = 'xtls-rprx-vision'
                            if inbound['protocol'] != 'trojan': raw.pop('password')
                            else: raw.pop('id')
                        else:
                            inbounds = row['inbounds']
                        client = dict(raw)
                        if limit is not None: client['totalGB'] = limit
                        if expires is not None: client['expiryTime'] = expires*1000
                        if note is not None: client['comment'] = note
                        if 'enabled' in body: client['enable'] = body['enabled']
                        if kind == '3x-ui':
                            route = '/panel/api/clients/add' if operation == 'create' else '/panel/api/clients/update/' + identity(key)
                            payload = {'client': client, 'inboundIds': inbounds} if operation == 'create' else client
                            await upstream.call('POST', route, payload=payload)
                        else:
                            if operation == 'create': route = '/panel/api/inbounds/addClient'
                            else:
                                client_id = raw.get('id') or raw.get('password')
                                if not client_id:
                                    raise ValueError('این پروتکل برای ویرایش کاربر پشتیبانی نمی‌شود.')
                                route = '/panel/api/inbounds/updateClient/' + identity(client_id)
                            await upstream.call('POST', route, data={'id': inbounds[0], 'settings': json.dumps({'clients': [client]})})
                    # Deliberately log identifiers, never client profiles or upstream bodies.
                self.store.event('ecosystem-user', {'provider': provider, 'operation': operation})
                return {'ok': True, 'message': 'درخواست توسط API مقصد پذیرفته شد؛ وضعیت و انتشار روی نودها را بررسی کن.'}

    async def inbound(self, provider, body):
        fields(body, ('name', 'port', 'server_name', 'apply'), ('name', 'port', 'server_name', 'apply'))
        name = text(body['name'], 64)
        port = number(body['port'], 65535)
        server = text(body['server_name'], 253)
        if port < 1024 or port in (20539, 20540, 20541):
            raise ValueError('پورت مقصد باید بین ۱۰۲۴ و ۶۵۵۳۵ و خارج از پورت‌های مدیریت backend باشد.')
        if not re.fullmatch(r'(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,63}', server):
            raise ValueError('برای Reality یک نام دامنهٔ TLS معتبر، بدون scheme یا پورت وارد کن.')
        if type(body['apply']) is not bool:
            raise ValueError('وضعیت اعمال معتبر نیست.')
        config = self.find(provider)
        if config['kind'] == 'pasarguard':
            raise ValueError('ساخت inbound در این مرحله از پنل PasarGuard انجام می‌شود؛ مدیریت کاربران در Donino فعال است.')
        plan = {'name': name, 'protocol': 'VLESS / TCP / Reality', 'listen': '127.0.0.1',
                'port': port, 'server_name': server, 'provider': self.public(config),
                'tunnel_target': '127.0.0.1:'+str(port), 'users': 0}
        if not body['apply']:
            return {'preview': plan}
        if not config['writable']:
            raise ValueError('این اتصال اجازهٔ ساخت inbound ندارد.')
        async with self.writes:
            async with self.upstream(config) as upstream:
                existing = await upstream.call('GET', '/panel/api/inbounds/list')
                if any(int(r['port']) == port for r in existing):
                    raise ValueError('این پورت در پنل مقصد ثبت شده است؛ پورت دیگری انتخاب کن.')
                keys = await upstream.call('GET', '/panel/api/server/getNewX25519Cert')
                if not isinstance(keys, dict) or not all(isinstance(keys.get(k), str) and re.fullmatch(r'[A-Za-z0-9_-]{43}', keys[k]) for k in ('privateKey', 'publicKey')):
                    raise ProviderError('ساخت کلید Reality در مقصد موفق نشد یا ساختار پاسخ سازگار نیست.')
                payload = {'remark': name, 'enable': True, 'listen': '127.0.0.1', 'port': port,
                           'protocol': 'vless', 'expiryTime': 0, 'total': 0,
                           'settings': json.dumps({'clients': [], 'decryption': 'none', 'fallbacks': []}),
                           'streamSettings': json.dumps({'network': 'tcp', 'security': 'reality',
                               'realitySettings': {'show': False, 'dest': server+':443', 'xver': 0,
                                   'serverNames': [server], 'privateKey': keys['privateKey'],
                                   'shortIds': [secrets.token_hex(8)],
                                   'settings': {'publicKey': keys['publicKey'], 'fingerprint': 'chrome', 'spiderX': '/'}}}),
                           'sniffing': json.dumps({'enabled': False, 'destOverride': ['http', 'tls']})}
                result = await upstream.call('POST', '/panel/api/inbounds/add', data=payload)
                self.store.event('ecosystem-inbound', {'provider': provider, 'port': port})
                return {'ok': True, 'inbound': {**plan, 'id': result.get('id') if isinstance(result, dict) else None}}

    async def subscription(self, provider, key, public_host=None, public_port=None):
        config = self.find(provider)
        async with self.reads:
            async with self.upstream(config) as upstream:
                if config['kind'] == '3x-ui-legacy':
                    raise ValueError('اشتراک نسخهٔ قدیمی را از همان پنل دریافت کن؛ URL اشتراک حدس زده نمی‌شود.')
                if config['kind'] == 'pasarguard':
                    raw, _ = await self.user(upstream, key)
                    value = raw.get('subscription_url', '')
                    # Some installations return a same-origin relative subscription URL.
                    if value.startswith('/') and not value.startswith('//'):
                        u = urlsplit(config['url']); value = u.scheme + '://' + u.netloc + value
                    u = urlsplit(value)
                    if u.scheme not in ('https', 'http') or not u.hostname or u.username or u.password:
                        raise ValueError('URL اشتراک معتبر از مقصد دریافت نشد.')
                    if public_host or public_port:
                        raise ValueError('URL اشتراک PasarGuard از تنظیمات همان پنل می‌آید؛ دامنهٔ انتشار را در مقصد تنظیم کن.')
                    result = {'url': value, 'links': []}
                else:
                    links = await upstream.call('GET', '/panel/api/clients/links/' + identity(key))
                    if not isinstance(links, list) or not all(isinstance(i, str) for i in links):
                        raise ValueError('ساختار لینک اشتراک مقصد پشتیبانی نمی‌شود.')
                    if public_host:
                        links = delivery_links(links, public_host, public_port)
                    elif public_port:
                        raise ValueError('برای نگاشت پورت، آدرس عمومی هم لازم است.')
                    result = {'url': '', 'links': links}
        self.store.event('ecosystem-subscription', {'provider': provider})
        return result


def catalog():
    # Explicit capabilities, rather than presenting discovery as provisioning.
    rows = [
        ('xray', 'Xray', 'core', 'Xray', 'MPL-2.0', ['users', 'quota', 'expiry', 'subscription'], 'provider', 'https://github.com/XTLS/Xray-core'),
        ('wireguard', 'WireGuard', 'core', 'UDP', 'GPL-2.0', ['discovery', 'tunnel-mapping'], 'external', 'https://www.wireguard.com'),
        ('sing-box', 'sing-box', 'core', 'multi', 'GPL-3.0', ['discovery', 'logs', 'service-control'], 'external', 'https://github.com/SagerNet/sing-box'),
        ('hysteria', 'Hysteria 2', 'core', 'QUIC', 'MIT', [], 'planned', 'https://github.com/apernet/hysteria'),
        ('tuic', 'TUIC', 'core', 'QUIC', 'GPL-3.0', [], 'planned', 'https://github.com/tuic-protocol/tuic'),
        ('frp', 'FRP', 'tunnel', 'WSS / QUIC', 'Apache-2.0', ['install', 'pair', 'failover', 'tcp', 'udp-relay'], 'native', 'https://github.com/fatedier/frp'),
        ('backhaul', 'Backhaul', 'tunnel', 'WSS / TCP', 'AGPL-3.0', ['install', 'pair', 'failover', 'tcp', 'udp-relay'], 'native', 'https://github.com/Musixal/Backhaul'),
        ('backpack', 'BackPack', 'tunnel', 'WSS', 'AGPL-3.0', ['install', 'pair', 'failover', 'tcp', 'udp-relay'], 'native', 'https://github.com/AminMGMT/BackPack'),
        ('paqet', 'Paqet', 'tunnel', 'raw / KCP', 'MIT', ['install', 'pair', 'failover', 'tcp', 'udp', 'socks5'], 'native', 'https://github.com/hanselime/paqet'),
        ('browser-wss', 'BrowserLink', 'tunnel', 'browser / HTTPS', 'MIT', ['install', 'pair', 'tcp', 'udp-relay'], 'native', 'https://github.com/danialrad04-sketch/donino-tunnel'),
        ('donino-mux', 'Donino Mux', 'tunnel', 'multiplexed WSS', 'MIT', ['install', 'pair', 'tcp', 'udp-relay'], 'native', 'https://github.com/danialrad04-sketch/donino-tunnel'),
        ('donino-continuum', 'Donino Continuum', 'tunnel', 'resumable WSS', 'MIT', ['install', 'pair', 'tcp', 'udp-relay'], 'native', 'https://github.com/danialrad04-sketch/donino-tunnel'),
        ('rathole', 'Rathole', 'tunnel', 'TCP', 'Apache-2.0', ['discovery', 'logs', 'service-control'], 'external', 'https://github.com/rapiz1/rathole'),
        ('gost', 'GOST', 'tunnel', 'multi', 'MIT', ['discovery', 'logs', 'service-control'], 'external', 'https://github.com/go-gost/gost'),
        ('chisel', 'Chisel', 'tunnel', 'HTTP / SSH', 'MIT', ['discovery', 'logs', 'service-control'], 'external', 'https://github.com/jpillora/chisel'),
        ('pasarguard', 'PasarGuard', 'panel', 'API', 'AGPL-3.0', ['users', 'quota', 'expiry', 'subscription', 'nodes', 'inbounds'], 'provider', 'https://github.com/PasarGuard/panel'),
        ('3x-ui', '3x-ui', 'panel', 'API v3 / legacy', 'GPL-3.0', ['users', 'quota', 'expiry', 'subscription', 'inbounds'], 'provider', 'https://github.com/MHSanaei/3x-ui'),
    ]
    result = [dict(zip(('id', 'name', 'category', 'protocol', 'license', 'capabilities', 'level', 'source'), r)) for r in rows]
    for row in result:
        row['experimental'] = row['id'] in ('backhaul', 'backpack', 'paqet', 'browser-wss', 'donino-mux', 'donino-continuum')
        row['note'] = 'این نسخهٔ Backhaul اعتبارسنجی کامل هویت سرور ندارد؛ مسیر پیش‌فرض نیست.' if row['id'] == 'backhaul' else 'محدودیت‌های نسخه و آزمون را در راهنمای موتور بررسی کن.' if row['experimental'] else ''
    return result
