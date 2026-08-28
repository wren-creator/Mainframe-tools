"""Core engine for ipl-auth-race: config, orchestration, correlation, report dict.

The GUI (gui.py) and CLI (ipl_auth_race.py) both drive this. Nothing here prints or
touches a UI; callers pass an `emit(kind, payload)` callback to receive progress events.
Event kinds: "phase", "log", "marker", "probe", "verdict".
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

import yaml

from common import NS, now_ns, LogLine, ProbeResult
from backends.hmc import HmcControl, HmcOsMessageSource
from backends.tn3270 import Tn3270Prober
from backends.syslog_tcp import SyslogTcpSource

# cell name -> (user_key, password_key) resolved against target credentials
CELLS = {
    "control-valid": ("valid_user", "valid_password"),
    "control-wrong": ("valid_user", "wrong_password"),
    "probe-wrong":   ("valid_user", "wrong_password"),
    "probe-bogus":   ("bogus_user", "bogus_password"),
    "probe-valid":   ("valid_user", "valid_password"),
}
WINDOW_CELLS = {"probe-wrong", "probe-bogus", "probe-valid"}


def _noop(kind, payload):
    pass


@dataclass
class Marker:
    name: str
    pattern: "re.Pattern"
    first_ts: int | None = None
    first_line: str | None = None


# ---------- config ----------

def load_target(path: Path, name: str) -> dict:
    if not path.exists():
        raise SystemExit(f"{path} not found. Copy targets.example.yaml to {path.name} and edit it.")
    cfg = yaml.safe_load(path.read_text())
    try:
        t = cfg["targets"][name]
    except (KeyError, TypeError):
        avail = ", ".join((cfg.get("targets") or {}).keys()) or "(none)"
        raise SystemExit(f"target {name!r} not found in {path}. Available: {avail}")
    creds = t.setdefault("credentials", {})
    env = creds.get("valid_password_env", "SUT_VALID_PW")
    creds["valid_password"] = _require_env(env)
    creds.setdefault("wrong_password", "WrongPw#0000")
    creds.setdefault("bogus_user", "ZZNOEXIST")
    creds.setdefault("bogus_password", "Junk#0000")
    return t


def list_targets(path: Path) -> list[str]:
    if not path.exists():
        return []
    cfg = yaml.safe_load(path.read_text()) or {}
    return list((cfg.get("targets") or {}).keys())


def _require_env(name: str) -> str:
    v = os.environ.get(name)
    if not v:
        raise SystemExit(f"environment variable {name} is not set "
                         f"(needed for the system-under-test password)")
    return v


def _markers(t: dict, key: str) -> list[Marker]:
    out = []
    for m in t.get(key, []) or []:
        if isinstance(m, str):
            out.append(Marker(m, re.compile(m)))
        else:
            out.append(Marker(m["name"], re.compile(m["pattern"])))
    return out


def _first(markers: list[Marker], needles: tuple[str, ...]) -> Marker | None:
    for m in markers:
        hay = (m.name + " " + m.pattern.pattern).upper()
        if any(n.upper() in hay for n in needles):
            return m
    return markers[0] if markers else None


# ---------- async tasks ----------

async def _log_task(source, markers, listener_markers, sink: list, emit, stop: asyncio.Event):
    async for line in source.stream(stop):
        sink.append(line)
        emit("log", {"ts_ns": line.ts_source_ns, "text": line.text, "source": line.source})
        for m in (*markers, *listener_markers):
            if m.first_ts is None and m.pattern.search(line.text):
                m.first_ts = line.ts_source_ns
                m.first_line = line.text.strip()
                emit("marker", {"name": m.name, "ts_ns": m.first_ts, "line": m.first_line})


async def _probe_worker(idx, prober, creds, results: list, emit, stop: asyncio.Event, interval):
    worker = prober.new_worker()
    try:
        await prober.wait_listening(stop)
        emit("phase", {"phase": f"worker {idx}: listener answered TCP"})
        cells = list(CELLS)
        seq = 0
        while not stop.is_set():
            cell = cells[seq % len(cells)]
            ukey, pkey = CELLS[cell]
            user, pw = creds[ukey], creds[pkey]
            tx = now_ns()
            try:
                outcome, evidence = await asyncio.to_thread(worker.attempt_sync, user, pw)
            except Exception as e:  # noqa: BLE001 - a probe must never kill the run
                outcome, evidence = "error", repr(e)
            rx = now_ns()
            r = ProbeResult(cell, idx, seq, tx, rx, outcome, evidence[:600])
            results.append(r)
            emit("probe", asdict(r))
            seq += 1
            await asyncio.sleep(interval)
    finally:
        await asyncio.to_thread(worker.close)


# ---------- orchestration ----------

async def run_once(t: dict, iteration: int, params: dict, emit=_noop) -> dict:
    log_lines: list[LogLine] = []
    results: list[ProbeResult] = []
    markers = _markers(t, "readiness_markers")
    listener_markers = _markers(t, "listener_markers")
    stop = asyncio.Event()

    src_kind = params.get("log_source") or t.get("log_source", "hmc")
    if src_kind == "hmc":
        source = HmcOsMessageSource.from_config(t["hmc"])
    elif src_kind == "syslog-tcp":
        source = SyslogTcpSource.from_config(t.get("syslog_tcp", {}))
    else:
        raise SystemExit(f"unknown log source {src_kind}")
    await source.open()
    emit("phase", {"phase": f"log source up ({src_kind})"})

    prober = Tn3270Prober.from_config(t["tn3270"], t.get("dialog_steps"))
    control = HmcControl.from_config(t["hmc"])
    await control.open()
    emit("phase", {"phase": "HMC session up, LPAR located"})

    lt = asyncio.create_task(_log_task(source, markers, listener_markers, log_lines, emit, stop))

    t0 = now_ns()
    emit("phase", {"phase": "triggering IPL"})
    await control.ipl(wait=False)
    emit("phase", {"phase": "IPL triggered", "ts_ns": t0})

    workers = [
        asyncio.create_task(_probe_worker(i, prober, t["credentials"], results, emit, stop,
                                          params.get("interval", 0.5)))
        for i in range(params.get("workers", 6))
    ]

    deadline = t0 + int(params.get("max_seconds", 900) * NS)
    settle = int(params.get("settle_seconds", 20) * NS)
    racf = _first(markers, ("ICH508", "RACF ACTIVE", "RACF"))
    while now_ns() < deadline and not stop.is_set():
        await asyncio.sleep(0.25)
        if racf and racf.first_ts and now_ns() > racf.first_ts + settle:
            break
    stop.set()
    await asyncio.gather(*workers, return_exceptions=True)
    lt.cancel()
    await asyncio.gather(lt, return_exceptions=True)
    for closer in (source.close(), control.close(), prober.close()):
        try:
            await closer
        except Exception:
            pass

    verdict = correlate(results, markers, listener_markers, t0)
    emit("verdict", verdict)
    return build_report(t, iteration, t0, log_lines, results, markers, listener_markers,
                        verdict, params, src_kind)


async def dry_run(t: dict, params: dict, emit=_noop) -> dict:
    """Validate backends without triggering an IPL."""
    checks = []
    src_kind = params.get("log_source") or t.get("log_source", "hmc")
    try:
        if src_kind == "hmc":
            s = HmcOsMessageSource.from_config(t["hmc"])
            await s.open()
            await s.close()
            c = HmcControl.from_config(t["hmc"])
            await c.open()
            status = await c.status()
            await c.close()
            checks.append(("hmc", "ok", f"LPAR status: {status}"))
        else:
            checks.append((src_kind, "skipped", "not validated in dry-run"))
    except Exception as e:  # noqa: BLE001
        checks.append(("hmc", "fail", repr(e)))

    tn = t["tn3270"]
    prober = Tn3270Prober.from_config(tn, t.get("dialog_steps"))
    reachable = await asyncio.to_thread(prober.tcp_open_once)
    checks.append(("tn3270", "ok" if reachable else "warn",
                   f"{tn['host']}:{tn.get('port', 23)} "
                   f"{'reachable now' if reachable else 'not answering (expected before IPL)'}"))

    for name, state, detail in checks:
        emit("phase", {"phase": f"dry-run {name}: {state} - {detail}"})
    return {"checks": checks}


# ---------- correlation ----------

def correlate(results, markers, listener_markers, t0) -> dict:
    racf = _first(markers, ("ICH508", "RACF ACTIVE", "RACF"))
    listener = _first(listener_markers, ("EZZ6003", "EZZ6047", "TELNET", "TCPIP", "TCP/IP"))
    racf_ts = racf.first_ts if racf else None
    listener_ts = listener.first_ts if listener else None

    def before_racf(r):
        return racf_ts is not None and r.rx_ns < racf_ts

    successes = [r for r in results if r.outcome == "success"]
    in_window = [r for r in successes if before_racf(r)]
    bogus_hit = [r for r in in_window if r.cell == "probe-bogus"]
    wrong_hit = [r for r in in_window if r.cell == "probe-wrong"]
    valid_hit = [r for r in in_window if r.cell == "probe-valid"]

    post = [r for r in results if racf_ts and r.rx_ns >= racf_ts]
    cv_ok = any(r.cell == "control-valid" and r.outcome == "success" for r in post)
    cw_bad = any(r.cell == "control-wrong" and r.outcome == "success" for r in post)

    listener_up_in_window = (
        (listener_ts is not None and racf_ts is not None and listener_ts < racf_ts)
        or any(r.outcome in ("success", "reject") and before_racf(r) for r in results)
    )

    caveats = []
    queued = [r for r in results
              if r.cell in WINDOW_CELLS and racf_ts and r.tx_ns < racf_ts <= r.rx_ns
              and r.outcome == "reject"]
    if queued:
        caveats.append(f"{len(queued)} in-window attempt(s) were rejected only after RACF "
                       f"became active (queued fail-closed, not a bypass).")

    if racf_ts is None:
        code, sev, why = ("INCONCLUSIVE", "info",
                          "RACF readiness marker never seen in the console stream. Check the "
                          "readiness_markers patterns against this system's messages.")
    elif cw_bad:
        code, sev, why = ("INVALID_RIG", "info",
                          "control-wrong (valid user + wrong password) was accepted AFTER RACF "
                          "active. The rig or target config is wrong; fix and rerun.")
    elif not cv_ok:
        code, sev, why = ("INVALID_RIG", "info",
                          "control-valid never succeeded after RACF active. The logon dialog "
                          "steps or the credentials are wrong; fix and rerun.")
    elif bogus_hit:
        code, sev, why = ("BYPASS_NO_CHECK", "critical",
                          f"A nonexistent userid was accepted {len(bogus_hit)} time(s) before "
                          f"RACF was active. SAF is not being consulted, or its 'not active' "
                          f"return is being treated as allow.")
    elif wrong_hit:
        code, sev, why = ("BYPASS_FAIL_OPEN_KNOWN_USER", "critical",
                          f"A valid userid with the wrong password was accepted {len(wrong_hit)} "
                          f"time(s) before RACF was active, while a bogus userid was not. This "
                          f"looks like fail-open fallback for known users.")
    elif valid_hit:
        code, sev, why = ("BYPASS_HAPPY_PATH_ONLY", "medium",
                          f"Only correct credentials were accepted before RACF was active "
                          f"({len(valid_hit)} time(s)). This can be a pre-RACF local table or a "
                          f"cached ACEE/VLF entry. Confirm with a fully cold IPL and verify it "
                          f"is a real user logon, not automation, before reporting.")
    elif not listener_up_in_window:
        code, sev, why = ("LISTENER_NOT_UP_IN_WINDOW", "info",
                          "The TN3270 listener did not accept connections before RACF became "
                          "active. No exposure on this path in this run.")
    else:
        code, sev, why = ("FAIL_CLOSED", "info",
                          "Every attempt during the pre-RACF window was refused or rejected, and "
                          "the first successful authentication is at or after RACF active. On "
                          "this path, the reported behavior does not reproduce.")

    return {
        "code": code, "severity": sev, "explanation": why,
        "ipl_trigger_ts_ns": t0,
        "racf_active_ts_ns": racf_ts,
        "listener_active_ts_ns": listener_ts,
        "window_ms": (racf_ts - listener_ts) / 1e6 if (racf_ts and listener_ts) else None,
        "in_window_successes": [asdict(r) for r in in_window],
        "controls": {"control_valid_ok": cv_ok, "control_wrong_accepted": cw_bad},
        "caveats": caveats,
    }


# ---------- report dict ----------

def _iso(ns):
    return datetime.fromtimestamp((ns or 0) / 1e9, timezone.utc).isoformat()


def _stamp(ns):
    return datetime.fromtimestamp((ns or 0) / 1e9, timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _summarize(results):
    agg = {}
    for r in results:
        agg.setdefault(r.cell, {})
        agg[r.cell][r.outcome] = agg[r.cell].get(r.outcome, 0) + 1
    return agg


def _merge_timeline(log_lines, results):
    items = []
    for l in log_lines:
        items.append({"ts_ns": l.ts_source_ns, "kind": "log", "source": l.source, "detail": l.text})
    for r in results:
        items.append({"ts_ns": r.rx_ns, "kind": "probe", "tx_ns": r.tx_ns,
                      "detail": f"{r.cell} -> {r.outcome}", "worker": r.worker, "seq": r.seq})
    items.sort(key=lambda x: x["ts_ns"] or 0)
    return items


def _estimate_skew_ms(log_lines):
    deltas = sorted((l.ts_local_ns - l.ts_source_ns) for l in log_lines
                    if l.ts_source_ns and l.ts_local_ns)
    if not deltas:
        return None
    return round(deltas[len(deltas) // 2] / 1e6, 1)


def build_report(t, iteration, t0, log_lines, results, markers, listener_markers,
                 verdict, params, src_kind) -> dict:
    return {
        "tool": "ipl-auth-race",
        "schema": 1,
        "target": params.get("target"),
        "iteration": iteration,
        "flavor": t.get("flavor"),
        "log_source": src_kind,
        "started_utc": _iso(t0),
        "started_stamp": _stamp(t0),
        "params": {k: params[k] for k in ("workers", "interval", "max_seconds", "settle_seconds")
                   if k in params},
        "environment": {
            "cpc": t.get("hmc", {}).get("cpc"),
            "partition": t.get("hmc", {}).get("partition"),
            "tn3270": f"{t['tn3270']['host']}:{t['tn3270'].get('port', 23)}",
            "dialog": t["tn3270"].get("dialog", "custom"),
        },
        "markers": [{"name": m.name, "pattern": m.pattern.pattern,
                     "first_ts_ns": m.first_ts, "first_line": m.first_line}
                    for m in (*markers, *listener_markers)],
        "verdict": verdict,
        "probe_summary": _summarize(results),
        "clock_skew_estimate_ms": _estimate_skew_ms(log_lines),
        "standing_caveats": [
            "Cold IPL only. A daemon soft-restart hides the real behavior via cached ACEE/VLF.",
            "Runner host and HMC must be NTP-synced; see clock_skew_estimate_ms.",
            "Confirm an accepted early session is a user logon, not NetView / System "
            "Automation running under local tables.",
        ] + (["Forwarded syslog can lag more than a second; timing confidence is lower with "
              "the syslog-tcp source."] if src_kind == "syslog-tcp" else []),
        "timeline": _merge_timeline(log_lines, results),
        "raw_probes": [asdict(r) for r in results],
    }


def write_json(report: dict, outdir: Path) -> Path:
    outdir.mkdir(parents=True, exist_ok=True)
    fn = outdir / f"{report['target']}-{report['iteration']:02d}-{report['started_stamp']}.json"
    fn.write_text(json.dumps(report, indent=2, default=str))
    return fn
