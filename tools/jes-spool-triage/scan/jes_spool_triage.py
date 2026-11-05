#!/usr/bin/env python3
"""Scan a flattened JES spool dump for RACF-access signals and exposed credentials.

Built for the situation where JESSPOOL-class protection is missing and PREFIX=*
OWNER=* in SDSF shows every job in the pool: instead of eyeballing held output
by hand, feed a text dump of that output through this script and get back a
ranked list of jobs worth a closer look before you submit your own RACF
database unload.

Input format -- one block per job, one sub-block per DD you captured:

    ===JOB JOBNAME=<name> JOBID=<id> OWNER=<id> CLASS=<c>===
    ===DD DDNAME=<ddname>===
    <raw lines from that DD, as they appeared in SDSF/held output>
    ===DD DDNAME=<ddname>===
    <raw lines from that DD>
    ===JOB JOBNAME=...
    ...

See collect/SCANSPL.rexx for a scaffolded SDSF REXX collector that can build
this dump automatically, or samples/sample_spool_dump.txt for what hand-built
input looks like if you're pasting SDSF browse screens together yourself.
"""

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

JOB_HEADER = re.compile(
    r"^===JOB\s+JOBNAME=(?P<jobname>\S+)\s+JOBID=(?P<jobid>\S+)\s+"
    r"OWNER=(?P<owner>\S+)(?:\s+CLASS=(?P<cls>\S+))?\s*===\s*$"
)
DD_HEADER = re.compile(r"^===DD\s+DDNAME=(?P<ddname>\S+)\s*===\s*$")

RACF_COMMANDS = re.compile(r"\b(ALTUSER|PERMIT|RDEFINE|SETROPTS|RVARY)\b", re.IGNORECASE)
RACF_RESOURCE = re.compile(r"\bSYS1\.RACF\b", re.IGNORECASE)
IRRDBU00 = re.compile(r"\bIRRDBU00\b", re.IGNORECASE)
ICH408I = re.compile(r"\bICH408I\b")
CLEAN_RC = re.compile(r"\b(?:COND(?:ITION)?\s*CODE|MAXCC|RC)\s*[=:]?\s*0*0000\b", re.IGNORECASE)
ADMIN_PGMS = re.compile(r"\bPGM=(IDCAMS|IEBCOPY|ADRDSSU|IEFBR14)\b", re.IGNORECASE)
SYSTEM_DATASETS = re.compile(
    r"\b(SYS1\.PARMLIB|SYS1\.PROCLIB|SYS1\.LINKLIB|SYS1\.VVDS|MASTER\s+CATALOG)\b", re.IGNORECASE
)
OPERATOR_HINTS = re.compile(
    r"(\bIFASMFDP\b|\bIFASMFR0\b|^\s*\$DA\b|^\s*D\s+U,|^\s*K\s+[A-Z])", re.IGNORECASE
)
PRIV_NAME_HINT = re.compile(r"\b(RACFADM\w*|SECADM\w*|SYSPROG\w*|OPER\w*)\b", re.IGNORECASE)
CREDENTIAL_PATTERNS = (
    re.compile(r"(?i)\b(password|pswd|pwd)\s*[=:]\s*\S+"),
    re.compile(r"(?i)\bpass\s*[=:]\s*\S+"),
    re.compile(r"(?i)\buser\s*[=:]\s*\S+"),
)

SEVERITY = {
    "RACF_SUCCESS_SIGNAL": "high",
    "RACF_BATCH_COMMAND": "high",
    "ADMIN_UTILITY_SYSTEM_DATASET": "medium",
    "OPERATOR_STYLE": "medium",
    "PRIVILEGED_NAMING_HINT": "info",
    "CREDENTIAL_STRING": "critical",
}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "info": 3}


@dataclass
class Finding:
    category: str
    severity: str
    jobname: str
    jobid: str
    owner: str
    ddname: str
    lineno: int
    text: str
    note: str = ""


@dataclass
class JobBlock:
    jobname: str
    jobid: str
    owner: str
    dds: dict = field(default_factory=dict)  # ddname -> list[str]


def parse_dump(path: Path):
    jobs = []
    current_job = None
    current_dd = None
    with path.open(encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.rstrip("\n")
            jm = JOB_HEADER.match(line)
            if jm:
                current_job = JobBlock(jm["jobname"], jm["jobid"], jm["owner"])
                jobs.append(current_job)
                current_dd = None
                continue
            dm = DD_HEADER.match(line)
            if dm:
                if current_job is None:
                    continue
                current_dd = dm["ddname"]
                current_job.dds[current_dd] = []
                continue
            if current_job is not None and current_dd is not None:
                current_job.dds[current_dd].append(line)
    return jobs


def scan_job(job: JobBlock):
    findings = []
    all_lines = [
        (ddname, lineno, text)
        for ddname, lines in job.dds.items()
        for lineno, text in enumerate(lines, start=1)
    ]

    has_408 = any(ICH408I.search(t) for _, _, t in all_lines)
    racf_hits = [(d, n, t) for d, n, t in all_lines if RACF_RESOURCE.search(t) or IRRDBU00.search(t)]
    has_clean_rc = any(CLEAN_RC.search(t) for _, _, t in all_lines)

    if racf_hits and not has_408 and has_clean_rc:
        ddname, lineno, text = racf_hits[0]
        findings.append(
            Finding(
                "RACF_SUCCESS_SIGNAL",
                SEVERITY["RACF_SUCCESS_SIGNAL"],
                job.jobname,
                job.jobid,
                job.owner,
                ddname,
                lineno,
                text.strip(),
                "Touches SYS1.RACF/IRRDBU00, clean completion code, no ICH408I anywhere "
                "in this job's captured output. Compare against your own failing attempt.",
            )
        )

    jcl_lines = job.dds.get("JESJCL", []) + job.dds.get("JCL", [])
    if any("IKJEFT01" in line.upper() for line in jcl_lines):
        for ddname in ("SYSTSIN", "SYSIN"):
            for lineno, text in enumerate(job.dds.get(ddname, []), start=1):
                if RACF_COMMANDS.search(text):
                    findings.append(
                        Finding(
                            "RACF_BATCH_COMMAND",
                            SEVERITY["RACF_BATCH_COMMAND"],
                            job.jobname,
                            job.jobid,
                            job.owner,
                            ddname,
                            lineno,
                            text.strip(),
                            "IKJEFT01 job issuing a RACF admin command; only works for "
                            "SPECIAL or the profile's own owner.",
                        )
                    )

    for ddname, lineno, text in all_lines:
        if SYSTEM_DATASETS.search(text) and ADMIN_PGMS.search(" ".join(jcl_lines)) and has_clean_rc:
            findings.append(
                Finding(
                    "ADMIN_UTILITY_SYSTEM_DATASET",
                    SEVERITY["ADMIN_UTILITY_SYSTEM_DATASET"],
                    job.jobname,
                    job.jobid,
                    job.owner,
                    ddname,
                    lineno,
                    text.strip(),
                    "Admin utility (IDCAMS/IEBCOPY/ADRDSSU/IEFBR14) referencing a system "
                    "dataset with a clean completion code nearby.",
                )
            )
        if OPERATOR_HINTS.search(text):
            findings.append(
                Finding(
                    "OPERATOR_STYLE",
                    SEVERITY["OPERATOR_STYLE"],
                    job.jobname,
                    job.jobid,
                    job.owner,
                    ddname,
                    lineno,
                    text.strip(),
                    "Looks like an operator console command or SMF dump utility.",
                )
            )
        for pat in CREDENTIAL_PATTERNS:
            if pat.search(text):
                findings.append(
                    Finding(
                        "CREDENTIAL_STRING",
                        SEVERITY["CREDENTIAL_STRING"],
                        job.jobname,
                        job.jobid,
                        job.owner,
                        ddname,
                        lineno,
                        text.strip(),
                        "Looks like an inline credential (PARM/SYSIN/SYSTSIN/FTP script). "
                        "Verify before using it -- don't assume it's live or in scope.",
                    )
                )
                break  # one hit per line is enough

    if PRIV_NAME_HINT.search(job.jobname) or PRIV_NAME_HINT.search(job.owner):
        findings.append(
            Finding(
                "PRIVILEGED_NAMING_HINT",
                SEVERITY["PRIVILEGED_NAMING_HINT"],
                job.jobname,
                job.jobid,
                job.owner,
                "-",
                0,
                f"JOBNAME={job.jobname} OWNER={job.owner}",
                "Naming convention suggests a privileged ID. Lead only, not proof -- "
                "confirm with LISTUSER before relying on it.",
            )
        )

    return findings


def scan_dump(path: Path):
    findings = []
    for job in parse_dump(path):
        findings.extend(scan_job(job))
    return findings


def render_text_report(findings):
    if not findings:
        return "No signals found in this dump.\n"
    findings = sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.jobname, f.lineno))
    lines = []
    for f in findings:
        lines.append(
            f"[{f.severity.upper():8}] {f.category:28} {f.jobname}/{f.jobid} "
            f"(owner={f.owner}) {f.ddname}:{f.lineno}\n"
            f"    {f.text}\n"
            f"    -> {f.note}"
        )
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("dump", type=Path, help="flattened JES spool dump (see module docstring)")
    ap.add_argument("--json", type=Path, help="also write findings as JSON to this path")
    args = ap.parse_args(argv)

    findings = scan_dump(args.dump)
    sys.stdout.write(render_text_report(findings))

    if args.json:
        args.json.write_text(json.dumps([asdict(f) for f in findings], indent=2))
        print(f"\nWrote {len(findings)} findings to {args.json}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
