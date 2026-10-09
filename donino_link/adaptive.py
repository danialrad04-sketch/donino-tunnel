"""Bounded, explainable scheduling of NEW streams over existing transports.

No new wire protocol, cryptography, packet camouflage, or stream replay.
Scores are heuristic costs, not bandwidth or packet-loss measurements.
"""
import math
import time
from collections import deque
from dataclasses import dataclass, field


@dataclass
class Quality:
    latency: float | None = None
    jitter: float = 0
    pressure: float = 0
    pressure_at: float = 0
    last_success: float | None = None
    outcomes: deque = field(default_factory=lambda: deque(maxlen=32))

    def probe(self, latency, now):
        self.outcomes.append(latency is not None)
        if latency is None:return
        latency=min(60000,max(0,latency))
        if self.latency is not None:
            self.jitter=.25*abs(latency-self.latency)+.75*self.jitter
            self.latency=.25*latency+.75*self.latency
        else:self.latency=latency
        self.last_success=now

    def drain(self, seconds, now):
        self.pressure=.2*min(5000,max(0,seconds*1000))+.8*self.pressure
        self.pressure_at=now

    def details(self, active, priority, timeout, now):
        failure_fraction=1-sum(self.outcomes)/len(self.outcomes) if self.outcomes else 0
        pressure=self.pressure*math.exp(-max(0,now-self.pressure_at)/15)
        latency=self.latency if self.latency is not None else timeout*1000
        cost=latency+2*self.jitter+failure_fraction*timeout*1000+2*pressure+active*max(10,latency)*.1+priority
        return {'cost':round(cost,3),'probe_ms':self.latency,'jitter_ms':round(self.jitter,3),
                'probe_failure_fraction':round(failure_fraction,3),'drain_pressure_ms':round(pressure,3),
                'samples':len(self.outcomes),'probe_age_seconds':None if self.last_success is None else round(max(0,now-self.last_success),3)}


class AdaptiveRouter:
    def __init__(self, policy, clock=time.monotonic):
        self.policy,self.clock=policy,clock
        self.leaders={}

    def details(self,path):
        return path.quality.details(path.active,path.config.get('priority',100),self.policy['connect_timeout'],self.clock())

    def rank(self, paths, service, preferred):
        now=self.clock()
        ttl=max(3*self.policy['probe_interval'],2*self.policy['probe_timeout'])
        paths=[p for p in paths if p.quality.last_success is not None and 0<=now-p.quality.last_success<=ttl]
        paths.sort(key=lambda p:(p.config['id']!=preferred,self.details(p)['cost'],p.config['id']))
        if len(paths)<2 or paths[0].config['id']==preferred:return paths
        name,since=self.leaders.get(service,(None,0))
        leader=next((p for p in paths if p.config['id']==name),None)
        # Hold small improvements for ten seconds; bypass for major improvement
        # or four additional live streams. Unhealthy/stale paths never enter.
        if leader and now-since<10 and self.details(paths[0])['cost']>=.8*self.details(leader)['cost'] and leader.active<paths[0].active+4:
            paths.remove(leader);paths.insert(0,leader)
        return paths

    def selected(self, service, path):
        if self.leaders.get(service,(None,))[0]!=path.config['id']:
            self.leaders[service]=(path.config['id'],self.clock())
