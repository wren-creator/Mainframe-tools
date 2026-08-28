"""Client-facing HTML report for ipl-auth-race runs.

Self-contained (inline CSS), prints cleanly to PDF from any browser. Neutral,
professional tone: scope, method, result, risk, recommendation.
"""
from __future__ import annotations

import html
from datetime import datetime, timezone
from pathlib import Path

SEV_COLOR = {
    "critical": "#b3261e", "high": "#c2410c", "medium": "#b8860b",
    "low": "#3a7d34", "info": "#3a5f8a",
}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]

RECOMMENDATION = {
    "BYPASS_NO_CHECK": (
        "Report to IBM PSIRT as an authentication bypass. Until a fix is available, do not "
        "expose the TN3270 port to any untrusted network during IPL: delay the Telnet "
        "listener start until a console check confirms RACF is active, and restrict the "
        "port at the network layer to a management segment."),
    "BYPASS_FAIL_OPEN_KNOWN_USER": (
        "Report to IBM PSIRT. Apply the same interim containment. Note that the fallback "
        "accepts known userids with an incorrect password, which points at a fail-open "
        "path rather than a missing SAF call."),
    "BYPASS_HAPPY_PATH_ONLY": (
        "Do not report yet. Re-run from a fully cold IPL with VLF and any session-manager "
        "credential cache confirmed clear, and confirm the accepted session is an "
        "interactive user logon, not early automation. If it still reproduces with correct "
        "credentials only, treat it as a lower-severity ordering issue and raise it with "
        "IBM support."),
    "FAIL_CLOSED": (
        "No action. The listener rejected every attempt made before RACF was active. Keep "
        "this report as evidence the concern was tested and did not reproduce."),
    "DELAYED_FAIL_CLOSED": (
        "No action. In-window attempts were queued and correctly rejected once RACF came "
        "up. Keep as evidence."),
    "LISTENER_NOT_UP_IN_WINDOW": (
        "Inconclusive for this path. The listener never accepted a connection before RACF "
        "was active in this run, so there was nothing to bypass. Re-run; if it is always "
        "so, the startup ordering on this system already prevents the exposure."),
    "INVALID_RIG": (
        "Results not usable. A control check failed, which means the test rig or the "
        "target configuration is wrong. Fix and re-run before drawing any conclusion."),
    "INCONCLUSIVE": (
        "Results not usable. The RACF readiness marker was not seen. Correct the console "
        "message patterns for this system and re-run."),
}

_CSS = """
body{font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#1a1a1a;
 max-width:820px;margin:2rem auto;padding:0 1.25rem}
h1{font-size:1.5rem;margin:0 0 .25rem}
h2{font-size:1.1rem;margin:1.75rem 0 .5rem;border-bottom:1px solid #ddd;padding-bottom:.25rem}
h3{font-size:.95rem;margin:1rem 0 .35rem;color:#555}
.sub{color:#666;margin:0 0 1.5rem}
.verdict{padding:1rem 1.25rem;border-radius:6px;color:#fff;margin:1rem 0}
.verdict .code{font-size:1.2rem;font-weight:700;letter-spacing:.02em}
table{border-collapse:collapse;width:100%;margin:.5rem 0}
th,td{border:1px solid #ddd;padding:.4rem .6rem;text-align:left;vertical-align:top}
th{background:#f4f4f4}
code{background:#f4f4f4;padding:.1rem .3rem;border-radius:3px;font-size:.9em}
.small{color:#666;font-size:.9rem}
ul{margin:.4rem 0 .4rem 1.2rem}
.tl{font:12px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;background:#fafafa;
 border:1px solid #eee;border-radius:4px;padding:.6rem;max-height:22rem;overflow:auto;
 white-space:pre}
@media print{body{margin:0;max-width:none}.tl{max-height:none}}
"""


def _esc(s):
    return html.escape(str(s if s is not None else ""))


def _fmt_ts(ns):
    if not ns:
        return "-"
    return datetime.fromtimestamp(ns / 1e9, timezone.utc).strftime("%H:%M:%S.%f")[:-3] + "Z"


def _verdict_block(v):
    color = SEV_COLOR.get(v["severity"], "#444")
    return (f'<div class="verdict" style="background:{color}">'
            f'<div class="code">{_esc(v["code"])}</div>'
            f'<div>Severity: {_esc(v["severity"].upper())}</div></div>'
            f'<p>{_esc(v["explanation"])}</p>')


def _iter_section(rep):
    v = rep["verdict"]
    rows = "".join(
        f"<tr><td>{_esc(cell)}</td><td>"
        + " ".join(f"{_esc(k)}={_esc(n)}" for k, n in sorted(outc.items()))
        + "</td></tr>"
        for cell, outc in sorted(rep["probe_summary"].items()))
    markers = "".join(
        f"<tr><td>{_esc(m['name'])}</td><td><code>{_esc(m['pattern'])}</code></td>"
        f"<td>{_fmt_ts(m['first_ts_ns'])}</td></tr>"
        for m in rep["markers"])
    tl = "\n".join(
        f"{_fmt_ts(it['ts_ns'])}  {it['kind']:<5} {_esc(it['detail'])[:140]}"
        for it in rep["timeline"])
    win = v.get("window_ms")
    return f"""
    <h2>Iteration {rep['iteration']}</h2>
    {_verdict_block(v)}
    <table>
      <tr><th>IPL triggered</th><td>{_esc(rep['started_utc'])}</td></tr>
      <tr><th>Listener accepted TCP</th><td>{_fmt_ts(v['listener_active_ts_ns'])}</td></tr>
      <tr><th>RACF active</th><td>{_fmt_ts(v['racf_active_ts_ns'])}</td></tr>
      <tr><th>Exposure window</th><td>{('%.0f ms' % win) if win else 'n/a'}</td></tr>
      <tr><th>Controls</th><td>valid logon works: {v['controls']['control_valid_ok']}
        &nbsp;|&nbsp; wrong password accepted after RACF up:
        {v['controls']['control_wrong_accepted']}</td></tr>
      <tr><th>Clock skew estimate</th><td>{_esc(rep['clock_skew_estimate_ms'])} ms</td></tr>
    </table>
    <h3>Probe results by credential class</h3>
    <table><tr><th>Class</th><th>Outcomes</th></tr>{rows}</table>
    <h3>Readiness / listener markers</h3>
    <table><tr><th>Marker</th><th>Pattern</th><th>First seen</th></tr>{markers}</table>
    <h3>Correlated timeline</h3>
    <div class="tl">{_esc(tl)}</div>
    """


def build_client_report(reports: list[dict]) -> str:
    first = reports[0]
    env = first["environment"]
    gen = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    codes = [r["verdict"]["code"] for r in reports]
    worst = min(reports, key=lambda r: SEV_ORDER.index(r["verdict"]["severity"]))["verdict"]
    rec = RECOMMENDATION.get(worst["code"], "See per-iteration detail.")
    caveats = "".join(f"<li>{_esc(c)}</li>" for c in first["standing_caveats"])
    extra = "".join(f"<li>{_esc(c)}</li>"
                    for r in reports for c in r["verdict"].get("caveats", []))
    iters = "".join(_iter_section(r) for r in reports)
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>IPL Authentication Race Check</title><style>{_CSS}</style></head><body>
<h1>IPL Authentication Race Check</h1>
<p class="sub">TN3270 credential validation during the IPL window, before RACF is active.<br>
Generated {gen}. Iterations: {len(reports)} ({', '.join(_esc(c) for c in codes)}).</p>

<h2>Scope</h2>
<table>
  <tr><th>CPC / partition</th><td>{_esc(env['cpc'])} / {_esc(env['partition'])}</td></tr>
  <tr><th>Listener tested</th><td>TN3270 at {_esc(env['tn3270'])}
    (logon dialog: {_esc(env['dialog'])})</td></tr>
  <tr><th>Console source</th><td>{_esc(first['log_source'])}</td></tr>
  <tr><th>Method</th><td>Trigger a real IPL, attempt TN3270 logon from the moment the port
    answers using valid, wrong-password, and nonexistent-user credentials, and compare each
    attempt's response time against the RACF-active console message.</td></tr>
</table>

<h2>Result</h2>
{_verdict_block(worst)}
<p><strong>Recommendation.</strong> {_esc(rec)}</p>

<h2>How to read this</h2>
<ul>
  <li><strong>Bypass verdicts</strong> mean a logon succeeded before RACF was active. The
    variant (no check vs fail-open for known users) tells IBM where to look.</li>
  <li><strong>FAIL_CLOSED</strong> means the concern was tested and did not reproduce.</li>
  <li><strong>INVALID_RIG / INCONCLUSIVE</strong> mean the test itself needs fixing before
    any conclusion can be drawn.</li>
</ul>

<h2>Caveats</h2>
<ul>{caveats}{extra}</ul>

{iters}

<h2>Disclosure</h2>
<p class="small">If a bypass verdict stands after the caveats above are cleared, the
finding should go to IBM PSIRT (Product Security Incident Response Team) through their
vulnerability reporting channel, with the per-iteration timelines and the z/OS release and
PTF level attached. It should not be posted publicly before IBM has responded.</p>
</body></html>"""


def write_client_report(reports: list[dict], outdir: Path) -> Path:
    outdir.mkdir(parents=True, exist_ok=True)
    tag = f"{reports[0]['target']}-{reports[0]['started_stamp']}"
    fn = outdir / f"client-report-{tag}.html"
    fn.write_text(build_client_report(reports))
    return fn
