import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, AsyncMock
from aiohttp import web
from aiohttp.test_utils import TestServer
from donino_link.config import atomic_json
from donino_link.ecosystem import Ecosystem
from donino_link.store import Store
from donino_link.vpn_bridge import validate, remote


class BridgeTests(unittest.IsolatedAsyncioTestCase):
    def test_allowlist_does_not_expose_generic_vendor_admin_api(self):
        for method,route in [('GET','/panel/api/clients/list'),('POST','/panel/api/inbounds/add'),
                             ('POST','/panel/api/clients/update/user%40test')]:
            self.assertEqual(validate({'method':method,'route':route})['route'],route)
        for request in ({'method':'POST','route':'/panel/api/server/updateXray'},
                        {'method':'GET','route':'/panel/api/server/getDb'},
                        {'method':'GET','route':'/panel/api/clients/list?url=https://evil'},
                        {'method':'GET','route':'/panel/api/clients/list','url':'http://evil'},
                        {'method':'POST','route':'/panel/api/inbounds/add','data':{},'payload':{}},
                        {'method':'GET','route':'/panel/api/clients/list','data':{}}):
            with self.assertRaises(ValueError):validate(request)

    async def test_remote_bootstrap_returns_only_pair_reference_not_vendor_token(self):
        profile={'id':'a'*32,'name':'outside','host':'2001:db8::1','agent_port':9444,'agent_token':'PRIVATE-PAIR-TOKEN'}
        class Worker:
            def profile(self, identifier):
                if identifier!=profile['id']:raise ValueError('unknown profile')
                return profile
        call=AsyncMock(return_value={'installed':True,'active':True,'version':'v3.10.2'})
        with patch('donino_link.peer.peer_request',call):
            result=await remote(Worker(),{'profile_id':profile['id'],'operation':'install','confirm_install':True})
            self.assertEqual(result['peer_profile'],profile['id'])
            self.assertEqual(result['url'],'https://[2001:db8::1]:9444')
            self.assertNotIn('PRIVATE-PAIR-TOKEN',json.dumps(result))
            self.assertNotIn('token',result)
            call.assert_awaited_once_with(profile,'/vpn-backend',{'operation':'install','confirm_install':True})
        with self.assertRaises(ValueError):await remote(Worker(),{'profile_id':profile['id'],'operation':'install'})

    async def test_adapter_uses_fixed_unix_bridge_and_credential_free_pair_reference(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);store=Store(root/'state.db');eco=Ecosystem(store,root/'connections.json');calls=[]
            async def bridge(request):
                body=await request.json();calls.append(body)
                self.assertEqual(request.path,'/vpn-backend-api')
                self.assertEqual(body['profile_id'],'a'*32)
                validate(body['request'])
                if body['request']['route'].endswith('/clients/list'):
                    # >64 KiB validates fragmented responses through the bridge.
                    obj=[{'id':n,'uuid':'SECRET-UUID','email':'user-'+str(n),'enable':True,'inboundIds':[1]} for n in range(1000)]
                else:obj={'client':{'id':1,'uuid':'SECRET-UUID','email':'user-0','enable':True},'inboundIds':[1]}
                return web.json_response({'success':True,'obj':obj})
            app=web.Application();app.router.add_post('/vpn-backend-api',bridge)
            runner=web.AppRunner(app);await runner.setup();socket=root/'bridge.sock';site=web.UnixSite(runner,str(socket));await site.start()
            try:
                with patch('donino_link.provision.SOCKET',socket):
                    connection=await eco.connect({'name':'outside','kind':'3x-ui','url':'https://outside.example.com:9444','writable':True},peer_profile='a'*32)
                    data=await eco.users(connection['id'],offset=50,limit=50)
                    self.assertEqual(data['total'],1000);self.assertEqual(data['users'][0]['username'],'user-50')
                    self.assertNotIn('SECRET-UUID',json.dumps(data))
                self.assertTrue(calls)
                persisted=json.loads((root/'connections.json').read_text())[0]
                self.assertNotIn('token',persisted)
                self.assertEqual(persisted['peer_profile'],'a'*32)
                with self.assertRaises(ValueError):
                    await eco.connect({'name':'bad','kind':'3x-ui','url':'https://bad.example.com','peer_profile':'a'*32})
            finally:await runner.cleanup();store.close()
