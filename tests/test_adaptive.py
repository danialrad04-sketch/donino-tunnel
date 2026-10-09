import tempfile
import unittest
from pathlib import Path
from donino_link.adaptive import Quality,AdaptiveRouter
from donino_link.gateway import Gateway,PathState
from donino_link.store import Store


class AdaptiveTests(unittest.TestCase):
    def setUp(self):
        self.now=100
        self.policy={'connect_timeout':2,'probe_interval':3,'probe_timeout':2}
        self.router=AdaptiveRouter(self.policy,lambda:self.now)
        self.paths=[PathState({'id':n,'priority':p},healthy=True) for n,p in [('a',10),('b',20)]]
        for p in self.paths:p.quality.probe(50,self.now)

    def rank(self):return [p.config['id'] for p in self.router.rank(self.paths,'app',None)]

    def test_fast_backup_can_outweigh_fixed_priority(self):
        self.paths[0].quality.latency=500
        self.assertEqual(self.rank(),['b','a'])

    def test_fresh_signed_observation_is_required(self):
        self.now+=10;self.assertEqual(self.rank(),[])
        self.paths[1].quality.probe(50,self.now);self.assertEqual(self.rank(),['b'])

    def test_small_improvement_hold_then_release(self):
        self.router.selected('app',self.paths[1])
        self.assertEqual(self.rank()[0],'b')
        self.now+=10
        for p in self.paths:p.quality.probe(50,self.now)
        self.assertEqual(self.rank()[0],'a')

    def test_major_degradation_and_load_bypass_hold(self):
        self.router.selected('app',self.paths[0]);self.paths[0].quality.latency=500
        self.assertEqual(self.rank()[0],'b')
        self.paths[0].quality.latency=50;self.paths[0].active=4
        self.assertEqual(self.rank()[0],'b')

    def test_preference_cannot_override_stale_observation(self):
        self.assertEqual(self.router.rank(self.paths,'app','b')[0].config['id'],'b')
        self.paths[1].quality.last_success=0
        self.assertEqual(self.router.rank(self.paths,'app','b')[0].config['id'],'a')

    def test_failed_probe_and_pressure_have_bounded_decaying_cost(self):
        q=Quality();q.probe(20,self.now);before=q.details(0,0,2,self.now)['cost']
        q.probe(None,self.now);q.drain(100,self.now)
        during=q.details(0,0,2,self.now)['cost'];after=q.details(0,0,2,self.now+150)['cost']
        self.assertGreater(during,before);self.assertLess(after,during)
        for _ in range(100):q.probe(20,self.now)
        self.assertEqual(len(q.outcomes),32);self.assertEqual(q.details(0,0,2,self.now)['probe_failure_fraction'],0)

    def test_service_leaders_are_independent_and_ranking_is_read_only(self):
        self.router.selected('app',self.paths[1])
        self.assertEqual(self.rank()[0],'b')
        self.assertEqual(self.router.rank(self.paths,'other',None)[0].config['id'],'a')
        before=dict(self.router.leaders);self.rank();self.assertEqual(before,self.router.leaders)

    def test_gateway_operator_gates_and_persistence(self):
        with tempfile.TemporaryDirectory() as d:
            store=Store(Path(d)/'state.db')
            try:
                cfg={'paths':[{'id':n,'priority':p} for n,p in [('a',10),('b',20)]],'policy':self.policy}
                g=Gateway(cfg,store);g.router=self.router
                for p in g.paths.values():p.healthy=True;p.quality.probe(50,self.now)
                g.paths['a'].quality.latency=500
                self.assertEqual(g.candidates()[0].config['id'],'a')
                g.action(None,'adaptive');self.assertEqual(g.candidates()[0].config['id'],'b')
                self.assertTrue(Gateway(cfg,store).adaptive)
                g.paths['b'].remote={'services':{'app':False}}
                self.assertEqual(g.candidates('app')[0].config['id'],'a')
                g.action('a','drain');self.assertEqual(g.candidates('app'),[])
                g.action(None,'static');self.assertFalse(Gateway(cfg,store).adaptive)
            finally:store.close()
