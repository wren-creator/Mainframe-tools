"""Shared types and helpers for ipl-auth-race. No UI, no I/O."""
from __future__ import annotations

import time
from dataclasses import dataclass

NS = 1_000_000_000


def now_ns() -> int:
    return time.time_ns()


@dataclass
class LogLine:
    ts_source_ns: int   # timestamp from the log source (HMC / console), best effort
    ts_local_ns: int    # when this runner received the line
    text: str
    source: str


@dataclass
class ProbeResult:
    cell: str
    worker: int
    seq: int
    tx_ns: int          # attempt sent
    rx_ns: int          # response classified
    outcome: str        # success | reject | refused | timeout | error
    evidence: str
