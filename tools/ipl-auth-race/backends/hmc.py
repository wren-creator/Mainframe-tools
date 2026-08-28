"""HMC Web Services backend: trigger the IPL and stream LPAR OS messages.

Both classes open their own zhmcclient session. HMC credentials come from the
environment (HMC_USERID / HMC_PASSWORD); the target CPC/LPAR come from target config.

Note: zhmcclient's OS-message field names (`sequence-number`, `message-text`,
`timestamp`) are assumed here; adjust `_pull` if your zhmcclient version differs.
"""
from __future__ import annotations

import asyncio
import os
import time

try:
    import zhmcclient
except ImportError:
    zhmcclient = None


def _session(cfg: dict):
    if zhmcclient is None:
        raise RuntimeError("zhmcclient is not installed (pip install -r requirements.txt)")
    userid = os.environ.get("HMC_USERID") or cfg.get("userid")
    password = os.environ.get("HMC_PASSWORD")
    if not (userid and password):
        raise RuntimeError("set HMC_USERID and HMC_PASSWORD in the environment")
    return zhmcclient.Session(cfg["host"], userid, password,
                              verify_cert=cfg.get("verify_cert", False))


def _find_partition(session, cfg: dict):
    client = zhmcclient.Client(session)
    cpc = client.cpcs.find(name=cfg["cpc"])
    if cfg.get("mode", "classic") == "dpm":
        return cpc.partitions.find(name=cfg["partition"]), "dpm"
    return cpc.lpars.find(name=cfg["partition"]), "classic"


class HmcControl:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.session = None
        self.part = None
        self.mode = None

    @classmethod
    def from_config(cls, cfg):
        return cls(cfg)

    async def open(self):
        self.session = await asyncio.to_thread(_session, self.cfg)
        self.part, self.mode = await asyncio.to_thread(_find_partition, self.session, self.cfg)

    async def status(self) -> str:
        return await asyncio.to_thread(lambda: self.part.get_property("status"))

    async def ipl(self, wait: bool = False):
        load = self.cfg.get("load", {}) or {}

        def _do():
            if self.mode == "dpm":
                try:
                    self.part.stop(wait_for_completion=True)
                except Exception:
                    pass
                return self.part.start(wait_for_completion=wait)
            # classic mode
            if self.part.get_property("status") == "not-activated":
                self.part.activate(wait_for_completion=True, force=True)
            if load.get("from_profile"):
                return self.part.activate(wait_for_completion=wait, force=True)
            kw = {}
            if load.get("load_address"):
                kw["load_address"] = str(load["load_address"])
            if load.get("load_parameter"):
                kw["load_parameter"] = str(load["load_parameter"])
            return self.part.load(wait_for_completion=wait, force=True, **kw)

        return await asyncio.to_thread(_do)

    async def close(self):
        if self.session:
            await asyncio.to_thread(self.session.logoff)
            self.session = None


class HmcOsMessageSource:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.session = None
        self.part = None
        self._seq = -1

    @classmethod
    def from_config(cls, cfg):
        return cls(cfg)

    async def open(self):
        self.session = await asyncio.to_thread(_session, self.cfg)
        self.part, _ = await asyncio.to_thread(_find_partition, self.session, self.cfg)

    async def stream(self, stop):
        from common import LogLine
        poll = float(self.cfg.get("poll_interval", 0.2))
        while not stop.is_set():
            try:
                batch = await asyncio.to_thread(self._pull)
            except Exception as e:  # a log source must survive early-IPL errors
                batch = [("", f"[os-message poll error: {e!r}]", time.time_ns())]
            local = time.time_ns()
            for mid, text, ts_ns in batch:
                yield LogLine(ts_source_ns=ts_ns, ts_local_ns=local,
                              text=f"{mid} {text}".strip(), source="hmc")
            await asyncio.sleep(poll)

    def _pull(self):
        kw = {}
        if self._seq >= 0:
            kw["begin"] = self._seq + 1
        msgs = self.part.list_os_messages(**kw)
        out = []
        for m in msgs:
            self._seq = max(self._seq, int(m.get("sequence-number", self._seq)))
            ts = m.get("timestamp")
            ts_ns = int(ts) * 1_000_000 if ts else time.time_ns()  # HMC gives ms
            out.append((m.get("message-id", "") or "",
                        (m.get("message-text", "") or "").rstrip("\n"),
                        ts_ns))
        return out

    async def close(self):
        if self.session:
            await asyncio.to_thread(self.session.logoff)
            self.session = None
