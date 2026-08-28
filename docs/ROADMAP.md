# Roadmap

Short, actionable entries. `[ ]` not started, `[~]` in progress, `[x]` landed.

## RACF / z/OS

- [~] IPL auth-race detector: does the TN3270 listener authenticate before RACF is up, or
  fail closed? Drives a real IPL via the HMC, correlates probes against console markers.
  GUI plus client HTML report. z/VM covered by the same tool. (`tools/ipl-auth-race/`)
- [ ] IRRDBU00 unload parser: normalize the record types into something queryable
- [ ] Find users with excessive authority (SPECIAL, OPERATIONS, group-SPECIAL sprawl)
- [ ] Stale IDs: no login in N days, revoked-but-not-removed, expired passwords
- [ ] Dataset profiles with UACC above READ, and WARNING-mode profiles
- [ ] General resource profiles: over-broad access lists, unused profiles
- [ ] SMF type 80 review: failed access attempts, RACF command activity
- [ ] Started task and surrogate (SURROGAT) mapping

## Linux on Z

- [ ] On-host collector (shell, zero deps) that bundles config for offline review
- [ ] sudoers audit: NOPASSWD, ALL=(ALL), wildcard command paths
- [ ] PAM stack review, password policy, faillock/pam_tally
- [ ] SELinux state and unconfined domains
- [ ] CIS-style baseline diff for RHEL/SLES on s390x

## z/VM

- [ ] User directory parser: privilege classes, LOGONBY, unrestricted OPTION lines
- [ ] Minidisk access: shared links, write links, missing passwords
- [ ] RACF/VM vs plain directory drift

## Network / TN3270

- [ ] Port and TLS posture check for TN3270 / TN3270E endpoints
- [ ] Flag cleartext 3270 exposure and weak cipher suites
- [ ] SSH config audit for the Linux on Z fleet

## Cross-cutting

- [ ] Common report format (JSON + human text) shared shape across tools
- [ ] Severity model: critical / high / medium / low / info, defined once
- [ ] Sanitized sample inputs under each tool's `samples/`
