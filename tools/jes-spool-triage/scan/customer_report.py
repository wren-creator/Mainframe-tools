#!/usr/bin/env python3
"""Turn jes_spool_triage.py's JSON findings into a customer-facing write-up.

    python3 jes_spool_triage.py dump.txt --json findings.json
    python3 customer_report.py findings.json --customer "Acme Corp" -o report.md

Groups findings by category with a plain-language "why it matters" and a
remediation pointer, instead of the raw per-line scanner output. Exposed
credential text is redacted by default -- the job/DD/line location is kept
so the customer's team can still find and rotate it -- pass --no-redact if
you specifically want raw values in this copy. The full, unredacted detail
always stays in the JSON findings file and the scanner's own stdout report.
"""

import argparse
import json
from datetime import date
from pathlib import Path

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "info": 3}

CATEGORY_LABELS = {
    "RACF_SUCCESS_SIGNAL": "RACF database access visible in spool",
    "RACF_BATCH_COMMAND": "Batch RACF administration commands visible in spool",
    "ADMIN_UTILITY_SYSTEM_DATASET": "System-dataset maintenance visible in spool",
    "OPERATOR_STYLE": "Operator / SMF-utility activity visible in spool",
    "CREDENTIAL_STRING": "Credential exposed in job data",
    "PRIVILEGED_NAMING_HINT": "Privileged-looking job/owner naming (lead only)",
}

REMEDIATION = {
    "RACF_SUCCESS_SIGNAL": (
        "Activate the JESSPOOL general-resource class, if it is not already, "
        "and define profiles restricting READ access to a job's own held output "
        "to its owner. Until JESSPOOL is active and profiled, any ID that can "
        "reach SDSF ST/DA can read every other job's output, including other "
        "users' successful RACF database access."
    ),
    "RACF_BATCH_COMMAND": (
        "Same root cause: JESSPOOL exposure lets any ID read the JCL and "
        "SYSTSIN of jobs that run RACF administration commands. Restricting "
        "JESSPOOL closes the visibility; separately review which IDs actually "
        "hold SPECIAL or group-SPECIAL to close the authority itself."
    ),
    "ADMIN_UTILITY_SYSTEM_DATASET": (
        "Same JESSPOOL exposure applies to jobs performing system-dataset "
        "maintenance. Also confirm dataset profiles on SYS1.PARMLIB/PROCLIB/"
        "LINKLIB restrict UPDATE/ALTER to the IDs that actually need it."
    ),
    "OPERATOR_STYLE": (
        "Operator-class commands and SMF-dump utilities showing up in readable "
        "spool output is an information-disclosure risk on its own. Restricting "
        "JESSPOOL access addresses this along with the rest."
    ),
    "CREDENTIAL_STRING": (
        "Independent of the spool exposure: rotate any credential found this "
        "way, and move the batch job that uses it to a vaulted/managed-"
        "credential pattern instead of embedding it in job data. Restricting "
        "JESSPOOL limits who can see the next one; it doesn't fix the practice "
        "of inlining credentials."
    ),
    "PRIVILEGED_NAMING_HINT": (
        "A lead, not a finding on its own. Worth confirming the ID's actual "
        "RACF authority (LISTUSER) as part of a broader access review, "
        "independent of the spool issue."
    ),
}


def redact(text: str) -> str:
    if "=" in text:
        key, _, _ = text.partition("=")
        return f"{key}=██████ (redacted -- see internal findings log)"
    return "██████ (redacted -- see internal findings log)"


def render(data: dict, customer: str, do_redact: bool) -> str:
    summary = data.get("summary", {}) if isinstance(data, dict) else {}
    findings = data.get("findings", data) if isinstance(data, dict) else data
    findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))

    by_category = {}
    for f in findings:
        by_category.setdefault(f["category"], []).append(f)
    category_order = sorted(
        by_category,
        key=lambda c: min(SEVERITY_ORDER.get(f["severity"], 9) for f in by_category[c]),
    )

    counts_by_severity = {}
    for f in findings:
        counts_by_severity[f["severity"]] = counts_by_severity.get(f["severity"], 0) + 1

    lines = [
        "# JES Spool Exposure -- Findings Summary",
        "",
        f"**Customer:** {customer}  ",
        f"**Date:** {date.today().isoformat()}  ",
        "",
        "## Methodology",
        "",
        "JESSPOOL-class protection was not enforced for the tested login, so "
        "every job in the JES pool was visible via SDSF (`PREFIX=* OWNER=*`) "
        "regardless of job owner. Held output for jobs in scope was captured "
        "and scanned for signals of RACF database access, batch RACF "
        "administration, system-dataset maintenance, operator activity, "
        "exposed credentials, and privileged naming conventions.",
        "",
    ]

    if summary:
        lines += [
            "## Scope",
            "",
            f"- Jobs visible in the pool: {summary.get('total_jobs', 'n/a')}",
            f"- Jobs with captured output: {summary.get('jobs_with_output', 'n/a')}",
            f"- Jobs with no output to review: {summary.get('jobs_with_no_output', 'n/a')}",
            f"- Jobs producing one or more findings: {summary.get('jobs_with_findings', 'n/a')}",
            "",
        ]

    lines += ["## Findings by severity", ""]
    for sev in ("critical", "high", "medium", "info"):
        if sev in counts_by_severity:
            lines.append(f"- **{sev.upper()}:** {counts_by_severity[sev]}")
    lines.append("")

    for category in category_order:
        items = by_category[category]
        lines += [
            f"## {CATEGORY_LABELS.get(category, category)}",
            "",
            f"**Occurrences:** {len(items)}",
            "",
            f"**Why it matters:** {REMEDIATION.get(category, '')}",
            "",
            "**Examples:**",
            "",
        ]
        for f in items[:5]:
            text = f["text"]
            if do_redact and category == "CREDENTIAL_STRING":
                text = redact(text)
            lines.append(
                f"- `{f['jobname']}/{f['jobid']}` (owner `{f['owner']}`), "
                f"`{f['ddname']}:{f['lineno']}`: {text}"
            )
        if len(items) > 5:
            lines.append(f"- ...and {len(items) - 5} more -- see the internal findings log")
        lines.append("")

    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("findings", type=Path, help="JSON file written by jes_spool_triage.py --json")
    ap.add_argument("--customer", default="[customer name]", help="name to put in the report header")
    ap.add_argument("-o", "--out", type=Path, help="write the report here instead of stdout")
    ap.add_argument(
        "--no-redact", action="store_true", help="include raw credential values instead of redacting them"
    )
    args = ap.parse_args(argv)

    data = json.loads(args.findings.read_text())
    report = render(data, args.customer, do_redact=not args.no_redact)

    if args.out:
        args.out.write_text(report)
        print(f"Wrote report to {args.out}")
    else:
        print(report)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
