"""Narrow paired-agent bridge to our unprivileged, isolated VPN backend."""
import json
import re
from aiohttp import ClientSession, ClientTimeout
from .ecosystem import fields, ProviderError, MAX_BODY
from .vpn_backend import Backend

SEGMENT = r'[A-Za-z0-9_.%:@+\-]{1,768}'
ROUTES = {
    'GET': (r'/panel/api/clients/list', r'/panel/api/clients/get/'+SEGMENT,
            r'/panel/api/clients/links/'+SEGMENT, r'/panel/api/inbounds/list',
            r'/panel/api/inbounds/get/[1-9][0-9]{0,9}', r'/panel/api/server/getNewX25519Cert'),
    'POST': (r'/panel/api/clients/add', r'/panel/api/clients/update/'+SEGMENT,
             r'/panel/api/clients/resetTraffic/'+SEGMENT, r'/panel/api/inbounds/add',
             r'/panel/api/inbounds/addClient', r'/panel/api/inbounds/updateClient/'+SEGMENT,
             r'/panel/api/inbounds/[1-9][0-9]{0,9}/resetClientTraffic/'+SEGMENT),
}


def validate(body):
    fields(body, ('method','route','data','payload'), ('method','route'))
    method, route = body['method'], body['route']
    if not isinstance(method,str) or not isinstance(route,str) or method not in ROUTES or not any(re.fullmatch(p,route) for p in ROUTES[method]):
        raise ValueError('Unsupported paired backend API operation')
    if body.get('data') is not None and body.get('payload') is not None:
        raise ValueError('Choose JSON or form data')
    for key in ('data','payload'):
        if body.get(key) is not None and not isinstance(body[key],dict):
            raise ValueError('Backend body must be an object')
    if method == 'GET' and (body.get('data') is not None or body.get('payload') is not None):
        raise ValueError('Read operation cannot contain a body')
    return body


async def local_api(body, backend=None):
    body = validate(body)
    backend = backend or Backend()
    connection = json.loads((backend.private/'connection.json').read_text())
    if not re.fullmatch(r'http://127\.0\.0\.1:20539/[a-f0-9]{32}', connection['url']):
        raise ValueError('Invalid isolated backend receipt')
    async with ClientSession(timeout=ClientTimeout(total=20),trust_env=False) as session:
        async with session.request(body['method'], connection['url']+body['route'],
                headers={'Authorization':'Bearer '+connection['token']}, data=body.get('data'),
                json=body.get('payload'), allow_redirects=False) as response:
            if response.status not in (200,201):
                raise ProviderError('Isolated backend API returned HTTP '+str(response.status))
            chunks, length = [],0
            async for chunk in response.content.iter_chunked(65536):
                length += len(chunk)
                if length > MAX_BODY: raise ProviderError('Backend response exceeds 8 MiB')
                chunks.append(chunk)
            return json.loads(b''.join(chunks))


async def remote(worker, body, api=False):
    from .peer import peer_request
    fields(body, ('profile_id','request') if api else ('profile_id','confirm_install','operation'),
           ('profile_id','request') if api else ('profile_id','operation'))
    profile = worker.profile(body['profile_id'])
    if not profile.get('agent_token'):
        raise ValueError('Pair the HTTPS management agent first')
    if api:
        request = validate(body['request'])
        return await peer_request(profile,'/vpn-backend-api',request)
    operation = body['operation']
    if operation not in ('install','status') or (operation == 'install' and body.get('confirm_install') is not True):
        raise ValueError('Confirm the selected remote backend installation')
    result = await peer_request(profile,'/vpn-backend',{'operation':operation,'confirm_install':body.get('confirm_install',False)})
    if operation == 'status': return result
    host = '['+profile['host']+']' if ':' in profile['host'] else profile['host']
    # This URL identifies the pinned agent, not an exposed vendor panel. All
    # adapter traffic is sent through the fixed local root-worker bridge.
    return {'kind':'3x-ui','name':('Xray · '+profile['name'])[:64],
            'url':'https://'+host+':'+str(profile['agent_port']),
            'peer_profile':profile['id'],'writable':True,'installed':result['installed']}
