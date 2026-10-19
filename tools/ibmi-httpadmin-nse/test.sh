#!/usr/bin/env bash
# Runs ibmi-httpadmin-audit.nse against web3270's mock IBM i admin GUI on the
# real console ports, 2001 and 2010. Needs nmap, node, openssl, and those two
# ports free on 127.0.0.1. WEB3270 points at the web3270 Bridge_server dir.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
WEB3270="${WEB3270:-$HERE/../../../web3270/Bridge_server}"
TMP="$(mktemp -d)"
MOCK=""
stop() { [ -n "$MOCK" ] && kill "$MOCK" 2>/dev/null && wait "$MOCK" 2>/dev/null; MOCK=""; }
trap 'stop; rm -rf "$TMP"' EXIT

openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj /CN=AS400MOCK \
  -keyout "$TMP/key.pem" -out "$TMP/cert.pem" 2>/dev/null

start() { # mode
  stop
  node "$HERE/mock-servers.cjs" "$WEB3270" "$TMP/key.pem" "$TMP/cert.pem" "$1" > "$TMP/mock.log" 2>&1 &
  MOCK=$!
  for _ in $(seq 1 30); do grep -q ready "$TMP/mock.log" 2>/dev/null && return; sleep 0.2; done
  echo "mock ($1) did not start:"; cat "$TMP/mock.log"; exit 2
}

fail=0
run() { nmap -Pn -n -p "$1" --script "$HERE/ibmi-httpadmin-audit.nse" ${2:+--script-args "$2"} 127.0.0.1 2>&1; }
expect() { if grep -Eq "$3" <<<"$2"; then echo "ok   $1"; else echo "FAIL $1"; echo "$2"; fail=1; fi; }
reject() { if grep -Eq "$3" <<<"$2"; then echo "FAIL $1"; echo "$2"; fail=1; else echo "ok   $1"; fi; }
CRED="ibmi-httpadmin-audit.user=JSMITH,ibmi-httpadmin-audit.pass=Summer2026"

start unpatched
o=$(run 2001 "$CRED")
expect "unpatched: cleartext finding"   "$o" "cleartext port 2001"
expect "unpatched: reports OS release"  "$o" "OS release V7R4M0"
expect "unpatched: missing fix flagged" "$o" "CVE-2026-96119 is not installed"
expect "unpatched: verdict FINDING"     "$o" "verdict: FINDING"

o=$(run 2001)
reject "no creds: About page never read" "$o" "OS release V7R4M0"
expect "no creds: patch status unknown"  "$o" "admin_fix: unknown"

o=$(run 2001 "ibmi-httpadmin-audit.user=JSMITH,ibmi-httpadmin-audit.pass=nope")
expect "wrong password reported, not retried" "$o" "returned HTTP 401"

o=$(run 2010 "$CRED")
expect "TLS: reachable finding"  "$o" "reachable on TLS port 2010"
expect "TLS: self-signed noted"  "$o" "self-signed"
expect "TLS: fix status read"    "$o" "CVE-2026-96119 is not installed"

start patched
o=$(run 2001,2010 "$CRED")
reject "patched: no missing-fix finding" "$o" "not installed"
expect "patched: fix reported"           "$o" "fix reported as SJ11643"

start real401
o=$(run 2001)
expect "real IBM i banner (Apache, HTTP Admin realm) is recognized" "$o" "cleartext port 2001"

start other
o=$(run 2001 "$CRED")
reject "non-IBM i web server: stays quiet" "$o" "ibmi-httpadmin-audit"
stop

o=$(run 2001)
reject "nothing listening: stays quiet" "$o" "ibmi-httpadmin-audit"

[ $fail -eq 0 ] && echo "all passed"
exit $fail
