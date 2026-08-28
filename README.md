# Mainframe-tools

Security and auditing tools for mainframe and mainframe-adjacent systems: RACF and z/OS,
Linux on Z, z/VM, and the network layer that fronts them (TN3270, SSH, TLS posture).

Most shops still audit these platforms by hand, with a person reading a RACF database
unload line by line or eyeballing a `sudoers` file over a 3270 session. That doesn't
scale, and it misses things. The tools here take the artifacts you can already export,
a RACF DBUNLOAD, SMF records, a z/VM directory, a Linux host's config, and turn them
into findings a human can act on.

## How this repo is organized

Each tool is standalone. It lives in its own directory under `tools/`, brings its own
README, its own dependencies, and its own tests, and can be copied out and run on its
own without dragging the rest of the repo along. That matters when the box you're
auditing is locked down and you can only get one script onto it.

```
tools/
  <tool-name>/
    README.md      what it audits, how to run it, what the output means
    ...             implementation (Python, shell, or Go, whatever fits the job)
```

See [tools/README.md](tools/README.md) for the current index.

## Language

Mixed, on purpose. Python for anything that parses a big export and produces a report.
Shell for on-host collectors that need to run with nothing installed. Go where a single
static binary is the only thing that will land on a hardened host. Each tool's README
says what it needs.

## Targets

| Area              | What gets audited                                                        |
|-------------------|-------------------------------------------------------------------------|
| RACF / z/OS       | RACF DB unload, SMF records, dataset and general-resource profiles, TSO |
| Linux on Z        | RHEL/SLES on s390x: PAM, sudo, SELinux, CIS-style hardening checks      |
| z/VM              | User directory, privilege classes, RACF/VM, minidisk access            |
| Network / TN3270  | TN3270 exposure, session security, port and TLS posture               |

## Roadmap

See [docs/ROADMAP.md](docs/ROADMAP.md).

## Community and contact

- Slack community: britleydev.slack.com
- Consulting and speaking: https://britleyhoffconsulting.com
- Contact: britleyhoff@britleyhoffconsulting.com
