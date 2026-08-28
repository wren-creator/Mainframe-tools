"""TN3270 probe backend, built on py3270 (which drives the s3270 binary).

One Tn3270Worker owns one long-lived s3270 process and reconnects for each attempt, so
the tool is not forking a subprocess per probe. The logon dialog is data-driven: a list
of steps, either one of DEFAULT_DIALOGS or `dialog_steps` from targets.yaml.

Step keys: wait_field(bool), wait_text(str)+timeout, send(str, typed at cursor),
fill_after(label)+value, tab(int), pf(int), enter(bool), settle(seconds float).
"""
from __future__ import annotations

import asyncio
import socket
import time

try:
    from py3270 import Emulator
except ImportError:
    Emulator = None


DEFAULT_DIALOGS = {
    # VTAM USS screen -> TSO logon. Adjust to your front end (session manager, etc.).
    "tso_uss": [
        {"wait_field": True},
        {"send": "LOGON APPLID(TSO)", "enter": True},
        {"wait_text": "USERID", "timeout": 12},
        {"send": "{user}", "enter": True},
        {"wait_text": "PASSWORD", "timeout": 12},
        {"fill_after": "PASSWORD", "value": "{password}", "enter": True},
        {"settle": 2.5},
    ],
    # z/VM logo screen -> LOGON.
    "zvm_logo": [
        {"wait_field": True},
        {"send": "LOGON {user}", "enter": True},
        {"wait_text": "PASSWORD", "timeout": 12},
        {"send": "{password}", "enter": True},
        {"settle": 2.5},
    ],
}

DEFAULT_SUCCESS = ["READY", "Ready;", "ISPF", "LOGON IN PROGRESS", "LOGON AT", "RECONNECTED"]
DEFAULT_REJECT = ["IKJ56420I", "IKJ56421I", "ICH408I", "PASSWORD NOT AUTHORIZED",
                  "NOT AUTHORIZED", "HCPLGA050E", "HCPLGB054E", "HCPLGA054E",
                  "NOT IN CP DIRECTORY"]


class _Cfg:
    def __init__(self, host, port, tls, steps, success, reject, connect_timeout):
        self.host, self.port, self.tls = host, int(port), bool(tls)
        self.steps, self.success, self.reject = steps, success, reject
        self.connect_timeout = connect_timeout

    def target(self):
        return f'{"L:" if self.tls else ""}{self.host}:{self.port}'

    def classify(self, text: str) -> str:
        up = text.upper()
        if any(p.upper() in up for p in self.reject):
            return "reject"
        if any(p.upper() in up for p in self.success):
            return "success"
        return "reject"  # an unrecognised screen is not a confirmed login


class Tn3270Prober:
    def __init__(self, cfg: _Cfg):
        self.cfg = cfg

    @classmethod
    def from_config(cls, tn: dict, dialog_steps=None):
        dialog = tn.get("dialog", "tso_uss")
        steps = dialog_steps or DEFAULT_DIALOGS.get(dialog)
        if steps is None:
            raise RuntimeError(f"no dialog steps for {dialog!r}; set dialog_steps in targets.yaml")
        cl = tn.get("classify", {}) or {}
        return cls(_Cfg(tn["host"], tn.get("port", 23), tn.get("tls", False), steps,
                        cl.get("success", DEFAULT_SUCCESS), cl.get("reject", DEFAULT_REJECT),
                        tn.get("connect_timeout", 8)))

    def tcp_open_once(self) -> bool:
        try:
            with socket.create_connection((self.cfg.host, self.cfg.port), timeout=2):
                return True
        except OSError:
            return False

    async def wait_listening(self, stop):
        while not stop.is_set():
            if await asyncio.to_thread(self.tcp_open_once):
                return
            await asyncio.sleep(0.25)

    def new_worker(self):
        return Tn3270Worker(self.cfg)

    async def close(self):
        pass


class Tn3270Worker:
    def __init__(self, cfg: _Cfg):
        self.cfg = cfg
        self.em = None

    def _ensure(self):
        if self.em is None:
            if Emulator is None:
                raise RuntimeError("py3270 not installed, or s3270 not on PATH "
                                   "(macOS: brew install x3270)")
            self.em = Emulator(visible=False, timeout=str(self.cfg.connect_timeout))

    def attempt_sync(self, user: str, password: str):
        self._ensure()
        em = self.em
        try:
            em.exec_command(b"Disconnect")
        except Exception:
            pass
        em.connect(self.cfg.target())
        for step in self.cfg.steps:
            self._run_step(em, step, user, password)
        text = "\n".join(em.exec_command(b"Ascii").data or [])
        return self.cfg.classify(text), text[:600]

    def _run_step(self, em, step, user, password):
        def fmt(s):
            return s.replace("{user}", user).replace("{password}", password)

        if step.get("wait_field"):
            em.wait_for_field()
        if "wait_text" in step:
            self._wait_text(em, step["wait_text"], step.get("timeout", 10))
        if "fill_after" in step:
            self._move_after_label(em, step["fill_after"])
            em.send_string(fmt(step.get("value", "")))
        if "send" in step:
            em.send_string(fmt(step["send"]))
        for _ in range(int(step.get("tab", 0))):
            em.exec_command(b"Tab")
        if step.get("pf"):
            em.exec_command(f"PF({int(step['pf'])})".encode())
        if step.get("enter"):
            em.send_enter()
        if "settle" in step:
            time.sleep(float(step["settle"]))

    @staticmethod
    def _wait_text(em, needle, timeout):
        end = time.time() + timeout
        n = needle.upper()
        while time.time() < end:
            if n in "\n".join(em.exec_command(b"Ascii").data or []).upper():
                return
            time.sleep(0.2)

    @staticmethod
    def _move_after_label(em, label):
        rows = em.exec_command(b"Ascii").data or []
        L = label.upper()
        for r, line in enumerate(rows):
            c = line.upper().find(L)
            if c >= 0:
                em.exec_command(f"MoveCursor({r},{c + len(label)})".encode())
                em.exec_command(b"Tab")
                return

    def close(self):
        if self.em:
            try:
                self.em.terminate()
            except Exception:
                pass
            self.em = None
