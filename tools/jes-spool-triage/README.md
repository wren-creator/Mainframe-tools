# jes-spool-triage

**Target:** RACF / z/OS
**Language:** Python (scanner) + REXX/JCL (optional collector, scaffolded)

## What it audits

For an authorized pentest where JESSPOOL-class protection is missing or
misconfigured and SDSF's `PREFIX=* OWNER=*` shows every job in the pool:
this tool reads a text dump of that held output and ranks the jobs worth
a closer look before you submit your own RACF database unload
(`IRRDBU00`). It answers "who in this spool already has the access I'm
testing for, and did anyone leave a credential lying in their JCL."

It looks for six signal types, same ones you'd check by hand:

| Category | Severity | What it means |
|---|---|---|
| `RACF_SUCCESS_SIGNAL` | high | Job touches `SYS1.RACF.*`/`IRRDBU00`, clean completion code, no `ICH408I` anywhere in its output. Compare against your own denied attempt. |
| `RACF_BATCH_COMMAND` | high | `IKJEFT01` job issuing `ALTUSER`/`PERMIT`/`RDEFINE`/`SETROPTS`/`RVARY` -- only works for SPECIAL or the profile's own owner. |
| `ADMIN_UTILITY_SYSTEM_DATASET` | medium | `IDCAMS`/`IEBCOPY`/`ADRDSSU`/`IEFBR14` touching `SYS1.PARMLIB`/`PROCLIB`/`LINKLIB`/the master catalog, clean RC. |
| `OPERATOR_STYLE` | medium | Console-command or SMF-dump-utility patterns. |
| `CREDENTIAL_STRING` | critical | `PASSWORD=`/`PASS=`/`USER=`-shaped text in `SYSIN`/`SYSTSIN`/`PARM` -- a candidate credential, not a confirmed one. |
| `PRIVILEGED_NAMING_HINT` | info | Job name or owner looks like `RACFADM*`/`SECADM*`/`SYSPROG*`/`OPER*`. A lead, never proof. |

## Safety / scope notes

- **This is credential-hunting.** Only point it at a JES pool you have
  written authorization to test, and treat the raw dump and the JSON
  report as sensitive engagement data: don't commit them, don't leave
  them in a shared download folder.
- A credential found this way is a finding in its own right, whether or
  not you go on to use it. Log where and when you found it.
- Before using a candidate ID to run your own `IRRDBU00` job, get the
  engagement sponsor to confirm in writing that using an ID found in
  the open spool is in scope, or have them hand you one directly.
  "Spool is readable" doesn't automatically mean "any ID I find in it
  is cleared for use."
- Confirm a `PRIVILEGED_NAMING_HINT` or `RACF_SUCCESS_SIGNAL` lead with
  `LISTUSER <id>` (if your own authority allows it) before relying on
  it -- the cleanest proof is your own unload job completing under
  that ID with record counts in `SYSPRINT`.

## Input

The scanner (`scan/jes_spool_triage.py`) reads one flat text file: a
dump of held job output, one block per job, one sub-block per DD:

```
===JOB JOBNAME=<name> JOBID=<id> OWNER=<id> CLASS=<c>===
===DD DDNAME=<ddname>===
<raw lines from that DD, as they appeared in SDSF/held output>
===DD DDNAME=<ddname>===
<raw lines from that DD>
===JOB JOBNAME=...
```

Two ways to build that file:

1. **Manual (works today, no tuning needed).** In SDSF, `ST` with
   `PREFIX=* OWNER=*`, open each job's held output, and for the DDs you
   care about (`JESMSGLG`, `JESJCL`, `SYSTSIN`, `SYSIN`, `SYSPRINT`)
   paste the lines under the headers above into one file. Tedious on a
   big pool, but reliable, and it's exactly what the pasted-notes
   workflow (`FIND PASSWORD ALL`, etc.) already has you doing one
   screen at a time -- this just gives you something to run `FIND`
   against programmatically, across every job at once.
2. **Automated collector (`collect/SCANSPL.rexx` + `SCANSPL.jcl`).** An
   SDSF REXX exec run in batch under `ISPSTART` that walks the whole
   pool via `ISFCALLS`/`ISFEXEC`/`ISFACT` and writes the same format.
   **This is a scaffold, not validated against a live SDSF session** --
   the per-DD browse action's exact `PARM()`/`PARM2()` syntax varies by
   z/OS release. Read the warnings at the top of `SCANSPL.rexx`, test
   it against a sandbox/training LPAR first, and budget time to tune
   it. If the engagement window is too short for that, use the manual
   path.

Never commit a real dump. `samples/sample_spool_dump.txt` is sanitized
(fake job names, fake credential) and is what the format above looks
like filled in.

### At scale (hundreds or thousands of jobs)

The manual path (`S` to open a job, page through DDs with `PF7`/`PF8`,
`F3` back, repeat) does not scale to a pool that size -- it's the same
one-job-at-a-time walk whether you're doing it by hand or dictating it
to a screen-scraper, just slower by orders of magnitude than letting
SDSF enumerate its own job table. Two things worth trying on the live
pool, in order:

1. **SDSF's own bulk print.** Some SDSF releases let you mark several
   rows on `ST` (or just issue `PRINT ALL` while `PREFIX=*/OWNER=*` is
   filtering the panel) and write every selected job's output to one
   sequential dataset in a single operation, no per-job browsing. If
   that works on your system, download the resulting dataset and write
   a small converter to turn its banner format into the `===JOB===`/
   `===DD===` shape above -- paste me a sanitized sample of what it
   actually looks like and I'll write that converter against the real
   format instead of guessing at it.
2. **The REXX collector**, if (1) isn't available or doesn't scale far
   enough. It runs the `ST`/browse walk natively through SDSF's own
   API in one batch job instead of one 3270 round trip per job, so
   1000+ jobs finishes in minutes server-side rather than hours of
   screen navigation. Submit `SCANSPL.jcl` and send back whatever
   `SYSTSPRT`/job log output you get -- real error messages from your
   system are what the two `TUNE THIS` sections in `SCANSPL.rexx`
   actually need to get fixed, not more guessing.

Jobs with no held output at all are expected and handled: the scanner
just records a job header with no findings (see
`test_summarize_handles_job_with_no_dd_blocks` in the test suite).

## Running it

```
python3 scan/jes_spool_triage.py path/to/spool_dump.txt
python3 scan/jes_spool_triage.py path/to/spool_dump.txt --json findings.json
python3 scan/customer_report.py findings.json --customer "Acme Corp" -o report.md
```

No third-party dependencies -- standard library only.

## Output

`jes_spool_triage.py` prints a one-line scope summary (jobs visible,
jobs with captured output, jobs that produced findings), then a text
report to stdout, sorted critical-first, one finding per line plus the
matched text and why it was flagged:

```
Scanned 1247 jobs (812 with captured output, 435 with none); 37 jobs produced 54 findings.

[CRITICAL] CREDENTIAL_STRING            FTPNITE1/JOB09901 (owner=BATCHID1) SYSIN:3
    PASS=NotARealSecret123
    -> Looks like an inline credential (PARM/SYSIN/SYSTSIN/FTP script). ...
```

`--json` writes `{"summary": {...}, "findings": [...]}` -- the full,
unredacted detail, for your own working notes.

`customer_report.py` takes that JSON and renders a Markdown write-up
grouped by category, with a plain-language "why it matters" and a
remediation pointer per category (JESSPOOL class, dataset profiles,
credential rotation, etc.) instead of a raw per-line dump. Credential
values are redacted by default (`USER=██████`) with the job/DD/line
location kept so the finding is still traceable and actionable --
pass `--no-redact` if you specifically want raw values in that copy.

Both the dump and any JSON/report output you keep belong under
`samples/private/` or `reports/`, which `.gitignore` already excludes.
The customer report is still engagement data -- sanitize or handle it
per your data-handling agreement before it leaves your hands.

## Checks performed

- [x] RACF database/unload access with a clean RC and no `ICH408I`
- [x] Batch RACF commands run through `IKJEFT01`
- [x] Admin utilities touching system datasets with a clean RC
- [x] Operator-console / SMF-dump command patterns
- [x] Inline credential strings in `SYSIN`/`SYSTSIN`/`PARM`
- [x] Privileged-looking job/owner naming conventions (lead only)
- [ ] Automated SDSF collector validated against a live system

## Tests

```
cd scan
python3 -m pytest tests/
```
