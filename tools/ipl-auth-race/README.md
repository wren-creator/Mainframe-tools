# ipl-auth-race

Detects whether a TN3270 listener on z/OS or z/VM authenticates connections during the
IPL window *before* RACF is initialized, or whether it fails closed.

**Target:** RACF / z/OS, z/VM
**Language:** Python

## What it audits

After an IPL, TCP/IP and the TN3270 listener can start accepting connections before RACF
has finished initializing and opened its database. If the listener mishandles the SAF
"subsystem not active" return (SAF RC=4) by falling open, or does not call SAF at all that
early, credentials are not really checked during that window.

This tool drives a real IPL, hits the TN3270 logon with a matrix of good and bad
credentials from the moment the port answers, watches the operator console for RACF
readiness, and correlates the two timelines. Output is a verdict: bypass confirmed (and
which kind), fails closed (false alarm), or inconclusive.

Run it against a test LPAR you control. It triggers IPLs.

## Interfaces

- **GUI** (`python gui.py`): pick a target, run "Test connection" to validate access
  without an IPL, then "Run check" to drive the IPL and probe loop. Live console and
  probe stream, a colour-coded verdict banner, and a "Save client report" button.
- **CLI** (`python ipl_auth_race.py`): same engine, for scripted or headless runs. Add
  `--client-report` to also emit the HTML.
- **Client report** (`report.py`): a self-contained HTML page, scope / method / result /
  risk / recommendation, that prints cleanly to PDF. This is the deliverable for the
  system owner; the JSON alongside it is the raw evidence.

## How it works

1. **Log source** starts first. Polls the LPAR's operating-system messages through the HMC
   Web Services API, timestamps every line, and flags readiness markers
   (`ICH508I RACF ACTIVE`, `ICH502I`) and listener markers (`EZZ6003I`, `EZZ6047I`).
2. **Control backend** triggers the IPL through the same HMC API and records t0.
3. **Probe workers** retry the TCP connect until the listener answers, then loop a
   credential matrix, recording transmit and receive timestamps for every attempt:

   | Cell | Credentials | A "success" here reads as |
   |------|-------------|---------------------------|
   | `control-valid` | valid user + valid pw | rig sanity: the logon path works |
   | `control-wrong` | valid user + wrong pw | rig sanity: auth is normally enforced |
   | `probe-wrong` | valid user + wrong pw, in window | auth not enforced for known users |
   | `probe-bogus` | nonexistent user + junk pw, in window | SAF not consulted at all |
   | `probe-valid` | valid user + valid pw, in window | informational (watch for caching) |

4. **Correlator** compares each attempt's *receive* time to the RACF-active timestamp. A
   rejection that arrives after RACF is up, even if sent during the window, is a queued
   fail-closed, not a bypass.

## Verdicts

- `BYPASS_NO_CHECK` (critical): bogus user accepted before RACF active.
- `BYPASS_FAIL_OPEN_KNOWN_USER` (critical): valid user + wrong password accepted before
  RACF active, bogus user not.
- `BYPASS_HAPPY_PATH_ONLY` (medium): only correct credentials got in early. Could be a
  pre-RACF local table or cached ACEE/VLF. Investigate before reporting.
- `FAIL_CLOSED` (false alarm): every in-window attempt refused or rejected; first
  successful auth is at or after RACF active.
- `DELAYED_FAIL_CLOSED`: in-window attempts were queued and correctly rejected once RACF
  came up.
- `LISTENER_NOT_UP_IN_WINDOW`: the port never answered before RACF active. Nothing to
  bypass on this path.
- `INVALID_RIG`: a control failed. Results not trustworthy; fix config and rerun.
- `INCONCLUSIVE`: readiness marker never seen, or no probes landed in the window.

## Setup

- Python 3.11+, `pip install -r requirements.txt`.
- `s3270` on PATH (`brew install x3270`, or the x3270 suite for your OS). py3270 drives it.
- HMC Web Services API reachable, with a userid permitted to Load the target LPAR and read
  its OS messages.
- Copy `targets.example.yaml` to `targets.yaml` (gitignored) and fill it in. Passwords come
  from environment variables named in the file, never from the file itself.

```
export HMC_USERID=...
export HMC_PASSWORD=...
export SUT_VALID_PW=...        # name matches valid_password_env in targets.yaml

python gui.py                                          # GUI
python ipl_auth_race.py --target zos_test --dry-run    # validate access, no IPL
python ipl_auth_race.py --target zos_test --iterations 3 --client-report
```

## Output

- `out/<target>-<iter>-<timestamp>.json`: full merged timeline, per-cell probe counts,
  verdict, and caveats. The raw evidence.
- `out/client-report-<target>-<timestamp>.html`: the client-facing report (GUI "Save
  client report" button, or CLI `--client-report`). Open in a browser, print to PDF.

## Caveats baked into every report

- **Cold IPL only.** A daemon soft-restart leaves cached ACEEs / VLF entries that validate
  credentials without touching the RACF database, which masks the real behavior.
- **Clock skew.** Runner host and HMC must be NTP-synced. The report includes an estimated
  skew from comparing local receive time to HMC message timestamps.
- **Console delivery latency.** HMC OS-message polling is close to the source; forwarded
  syslog can lag more than a second. The `syslog-tcp` source is a fallback and its reports
  are marked lower-confidence on timing.
- **Legitimate early windows.** NetView / System Automation may run under local tables by
  design during early IPL. Confirm an accepted session is a real user logon, not
  automation, before calling it a bypass.

## Status

First cut. Two things need tuning against your environment before the numbers mean
anything:

- The logon dialog step interpreter (`backends/tn3270.py`, `DEFAULT_DIALOGS`) is a
  reasonable guess at a VTAM USS -> TSO logon and a z/VM logo logon. Adjust the steps, or
  set `dialog_steps` in `targets.yaml`, to match your actual panels.
- The z/VM RACF (RACFVM) readiness markers in `targets.example.yaml` are placeholders.
  Confirm them against a real z/VM IPL console log.

## Checks performed

- [x] TN3270 logon during the pre-RACF window with four credential classes
- [x] Console correlation against RACF readiness markers
- [x] Transmit vs receive timestamping to catch queued rejects
- [x] GUI front end with live stream and verdict banner
- [x] Client-facing HTML report (prints to PDF)
- [ ] FTP listener probe (same idea, different dialog)
- [ ] z/VM RACFVM readiness markers confirmed against a real IPL log
- [ ] Linux on Z path (SSH probe during boot before SSSD/PAM backends are up)
