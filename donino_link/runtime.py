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
        self.started=time.time();self.task=None

    async def publish(self):
        while True:
            self.write();await asyncio.sleep(1)

    def write(self):
        if not self.path or not self.path.parent.is_dir() or not os.access(self.path.parent,os.W_OK):return
        try:atomic_json(self.path,{'time':time.time(),'started':self.started,'pid':os.getpid(),'active':self.active,
                    'accepted':self.accepted,'bytes_up':self.bytes_up,'bytes_down':self.bytes_down})
        except OSError:pass

    async def start(self):
        if self.path:self.task=asyncio.create_task(self.publish())

    async def stop(self):
        if self.task:
            self.task.cancel()
            with contextlib.suppress(asyncio.CancelledError):await self.task
        self.write()
