"""Fallback log source: a tiny TCP server that timestamps forwarded syslog lines.

Point z/OS syslogd (or your automation product) at this host and port. Lower timing
confidence than the HMC source because of forwarding latency; reports built on this
source are flagged accordingly.
"""
from __future__ import annotations

import asyncio
import re
import time

_PRI = re.compile(r"^<\d+>")


class SyslogTcpSource:
    def __init__(self, bind: str, port: int):
        self.bind, self.port = bind, int(port)
        self._q: asyncio.Queue = asyncio.Queue()
        self._server = None

    @classmethod
    def from_config(cls, cfg: dict):
        return cls(cfg.get("bind", "0.0.0.0"), cfg.get("port", 5514))

    async def open(self):
        self._server = await asyncio.start_server(self._handle, self.bind, self.port)

    async def _handle(self, reader, _writer):
        while not reader.at_eof():
            raw = await reader.readline()
            if not raw:
                break
            now = time.time_ns()
            line = _PRI.sub("", raw.decode("latin-1", "replace")).rstrip("\r\n")
            await self._q.put((now, line))

    async def stream(self, stop):
        from common import LogLine
        while not stop.is_set():
            try:
                ts, line = await asyncio.wait_for(self._q.get(), timeout=0.5)
            except asyncio.TimeoutError:
                continue
            yield LogLine(ts_source_ns=ts, ts_local_ns=ts, text=line, source="syslog-tcp")

    async def close(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
