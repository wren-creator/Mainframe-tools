#!/usr/bin/env python3
"""CLI entry point for ipl-auth-race. For the GUI, run `python gui.py`. See README.md."""
from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

import engine
from report import write_client_report


def _emit(kind, payload):
    if kind == "log":
        print(f"  log  {payload['text'][:120]}")
    elif kind == "marker":
        print(f"  MARK {payload['name']}  @{payload['ts_ns']}")
    elif kind == "probe":
        print(f"  prb  {payload['cell']:<14} {payload['outcome']}")
    elif kind == "phase":
        print(f"* {payload['phase']}")
    elif kind == "verdict":
        print(f"\n== VERDICT: {payload['code']} ({payload['severity']}) ==\n  "
              f"{payload['explanation']}")


def main():
    ap = argparse.ArgumentParser(
        description="Detect a pre-RACF TN3270 auth bypass across an IPL")
    ap.add_argument("--target", required=True)
    ap.add_argument("--targets-file", default="targets.yaml", type=Path)
    ap.add_argument("--iterations", type=int, default=1)
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--interval", type=float, default=0.5,
                    help="seconds between attempts per worker")
    ap.add_argument("--max-seconds", type=float, default=900)
    ap.add_argument("--settle-seconds", type=float, default=20,
                    help="keep probing this long after RACF active")
    ap.add_argument("--log-source", choices=["hmc", "syslog-tcp"])
    ap.add_argument("--outdir", default="out", type=Path)
    ap.add_argument("--dry-run", action="store_true",
                    help="validate config and backends, do not IPL")
    ap.add_argument("--client-report", action="store_true",
                    help="also write the client-facing HTML report")
    args = ap.parse_args()

    t = engine.load_target(args.targets_file, args.target)
    params = {"target": args.target, "workers": args.workers, "interval": args.interval,
              "max_seconds": args.max_seconds, "settle_seconds": args.settle_seconds,
              "log_source": args.log_source}

    if args.dry_run:
        asyncio.run(engine.dry_run(t, params, _emit))
        return

    reports = []
    for i in range(1, args.iterations + 1):
        print(f"\n--- iteration {i}/{args.iterations} ---")
        rep = asyncio.run(engine.run_once(t, i, params, _emit))
        fn = engine.write_json(rep, args.outdir)
        print(f"  json: {fn}")
        reports.append(rep)

    if args.client_report:
        html = write_client_report(reports, args.outdir)
        print(f"\nclient report: {html}")

    if len(reports) > 1:
        print("\n== rollup ==")
        for r in reports:
            print(f"  iter {r['iteration']}: {r['verdict']['code']}")


if __name__ == "__main__":
    main()
