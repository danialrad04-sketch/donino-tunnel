"""Unprivileged foreign monitor: service state and fresh Iran probes differ."""
import asyncio
import contextlib
import subprocess
import time
from aiohttp import ClientSession,ClientTimeout,UnixConnector,ClientError
from .gateway import PathState
from .health import host_stats,target_status
from .provision import read_json
from .plan import TRANSPORTS
from .peer import SOCKET,digest


def unit_status(units):
    if not units:return []
    result=subprocess.run(['systemctl','show','--no-pager','--property=Id,ActiveState,SubState,NRestarts,MemoryCurrent,MainPID',*units],capture_output=True,text=True,timeout=8)
    if result.returncode:raise OSError('systemd status unavailable')
    rows=[]
    for block in result.stdout.strip().split('\n\n'):
        v=dict(line.split('=',1) for line in block.splitlines() if '=' in line)
        if v.get('Id') not in units:continue
        rows.append({'unit':v['Id'],'active':v.get('ActiveState')=='active','state':v.get('ActiveState','unknown'),
            'substate':v.get('SubState','unknown'),'restarts':int(v.get('NRestarts','0')),'pid':int(v.get('MainPID','0')),
            'memory':int(v['MemoryCurrent']) if v.get('MemoryCurrent','').isdigit() and int(v['MemoryCurrent'])<2**64-1 else None})
    return rows


class ForeignMonitor:
    def __init__(self,config,store):
        self.config,self.store=config,store
        self.started=time.time();self.paths={};self.task=None
        self.units=[];self.targets={};self.agent={'available':False};self.metrics_data=None
        self.active=self.accepted=self.rejected=0
        self.last_telemetry=0;self.previous_units={}
        for u in read_json('/etc/donino-link/current/install.json',{}).get('units',[]):
            name=u.removeprefix('donino-link-').removesuffix('.service')
            if name in TRANSPORTS:self.paths[name]=PathState({'id':name,'transport':name,'priority':100})

    async def collect(self):
        units=read_json('/etc/donino-link/current/install.json',{}).get('units',[])
        try:self.units=await asyncio.to_thread(unit_status,units)
        except (OSError,subprocess.SubprocessError):self.units=[]
        for row in self.units:
            if self.previous_units.get(row['unit'])!=row['state']:self.store.event('unit-state',{'unit':row['unit'],'state':row['state']})
        self.previous_units={r['unit']:r['state'] for r in self.units}
        targets=self.config.get('targets',{})
        results=await asyncio.gather(*(target_status(t) for t in targets.values()))
        self.targets={k:{'target':targets[k],'reachable':v} for k,v in zip(targets,results)}
        try:
            async with ClientSession(connector=UnixConnector(path=str(SOCKET)),timeout=ClientTimeout(total=8)) as session:
                async with session.get('http://localhost/state') as response:
                    if response.status!=200:raise OSError('agent unavailable')
                    self.agent=await response.json()
        except (OSError,ClientError,asyncio.TimeoutError):self.agent={'available':False}
        telemetry=self.agent.get('telemetry') or read_json('/var/lib/donino-link/peer-observations.json',{})
        fresh=0<=time.time()-telemetry.get('time',0)<=45 and telemetry.get('config_hash')==digest(self.config['health_key'])
        probes={p['path']:p for p in telemetry.get('probes',[])} if fresh else {}
        active={r['unit']:r['active'] for r in self.units}
        pids={r['unit']:r['pid'] for r in self.units}
        for name,path in self.paths.items():
            row=probes.get(name);before=path.healthy
            adapter_active=name=='browser-wss' or active.get('donino-link-framed.service',False)
            path.healthy=bool(active.get('donino-link-'+name+'.service') and adapter_active and row and row['ok'] and all(row.get('services',{}).values()) and all(results))
            path.error='' if path.healthy else ('unit-inactive' if active.get('donino-link-'+name+'.service') is False else 'awaiting-fresh-iran-probe' if not row else 'probe-or-origin-failed')
            path.latency_ms=row.get('latency_ms') if row else None
            if row and telemetry['time']!=self.last_telemetry:path.history.append({'time':telemetry['time'],'ok':path.healthy,'latency':path.latency_ms})
            if before!=path.healthy:self.store.event('path-health',{'path':name,'healthy':path.healthy})
        self.last_telemetry=telemetry.get('time',0)
        sources=[]
        for filename,unit in [('framed-foreign.json','donino-link-framed.service'),('browser-foreign.json','donino-link-browser-wss.service')]:
            data=read_json('/var/lib/donino-link/'+filename,{})
            if active.get(unit) and data.get('pid')==pids.get(unit) and 0<=time.time()-data.get('time',0)<10:sources.append(data)
        self.metrics_data={k:sum(s[k] for s in sources) for k in ['active','accepted','bytes_up','bytes_down']} if sources else None
        if self.metrics_data:self.active=self.metrics_data['active'];self.accepted=self.metrics_data['accepted']

    def snapshot(self):
        telemetry=self.agent.get('telemetry') or read_json('/var/lib/donino-link/peer-observations.json',{})
        fresh=0<=time.time()-telemetry.get('time',0)<=45 and telemetry.get('config_hash')==digest(self.config['health_key'])
        rows=[]
        for p in self.paths.values():
            row=p.snapshot();row.update(observation='fresh' if fresh else 'unknown',health_source='Iran signed round-trip probe')
            if not fresh:row['healthy']=False
            rows.append(row)
        return {'version':'0.1.0','role':'foreign','time':time.time(),'uptime':time.time()-self.started,'paused':False,'preferred':None,
            'selected':None,'active':self.metrics_data['active'] if self.metrics_data else None,
            'accepted':self.metrics_data['accepted'] if self.metrics_data else None,'rejected':None,'route_changes':None,
            'host':host_stats(),'paths':rows,'services':[],'events':self.store.events(),'units':self.units,'targets':self.targets,
            'foreign':self.agent,'metrics':self.metrics_data,'telemetry_fresh':fresh,'probe_time':telemetry.get('time'),
            'bootstrap':self.config.get('bootstrap',False),'public_address':self.config.get('public_address')}

    def action(self,*args):raise ValueError('route selection belongs on the Iran panel; use foreign service actions')

    async def start(self):
        await self.collect()
        async def poll():
            while True:
                await asyncio.sleep(5)
                try:await self.collect()
                except (OSError,ValueError,KeyError,ClientError):self.agent={'available':False}
        self.task=asyncio.create_task(poll())

    async def stop(self):
        if self.task:
            self.task.cancel()
            with contextlib.suppress(asyncio.CancelledError):await self.task
