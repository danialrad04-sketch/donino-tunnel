"""Optional, sanitized counters for the node's own stream relays."""
import asyncio
import contextlib
import os
import time
from pathlib import Path
from .config import atomic_json


class RuntimeStats:
    def __init__(self,path=None):
        self.path=Path(path) if path else None
        self.active=self.accepted=self.bytes_up=self.bytes_down=0
        self.started=time.time();self.task=None;self.details=None

    async def publish(self):
        while True:
            self.write();await asyncio.sleep(1)

    def write(self):
        if not self.path or not self.path.parent.is_dir() or not os.access(self.path.parent,os.W_OK):return
        row={'time':time.time(),'started':self.started,'pid':os.getpid(),'active':self.active,
             'accepted':self.accepted,'bytes_up':self.bytes_up,'bytes_down':self.bytes_down}
        if self.details:row['protocol']=self.details()
        try:atomic_json(self.path,row)
        except OSError:pass

    async def start(self):
        if self.path:self.task=asyncio.create_task(self.publish())

    async def stop(self):
        if self.task:
            self.task.cancel()
            with contextlib.suppress(asyncio.CancelledError):await self.task
        self.write()


def continuum_status(role, expected_pid=None):
    """Fresh process-local telemetry, never a substitute for signed probes."""
    import json
    try:
        row=json.loads(Path('/var/lib/donino-link/continuum-'+role+'.json').read_text())
        if not 0<=time.time()-row['time']<10 or (expected_pid is not None and row.get('pid')!=expected_pid):return None
        os.kill(row['pid'],0)
        value=row.get('protocol',{})
        keys=['connected_lanes','recovering_sessions','recoveries','expired','replayed_bytes','pending_bytes','recovery_seconds']
        if value.get('name')!='donino-continuum.v2' or any(type(value.get(k)) not in (int,float) or value[k]<0 for k in keys):return None
        return {k:value[k] for k in keys}
    except (OSError,ValueError,KeyError,TypeError):return None
