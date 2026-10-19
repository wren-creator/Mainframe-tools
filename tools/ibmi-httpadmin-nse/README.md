# ibmi-httpadmin-audit (nmap script)

**Target:** IBM i (HTTP Server Administration GUI, ports 2001 and 2010)
**Language:** Lua (NSE)

## What it audits

The IBM i HTTP Server Administration GUI is the ADMIN web console, and the
CVE-2026-96119 authenticated remote code execution lives behind it. This script
ports the HTTP Admin GUI Audit probe from web3270 so you can sweep a network
with nmap instead of driving the bridge one host at a time.

It is a read-only exposure check. It sends GETs only. It never submits a form,
never touches the Create HTTP Server page, never runs a command, and tries no
credential beyond the one pair you hand it. A missing fix is reported from what
the box says about itself on its About page, not by exploiting it.

## Running it

```
nmap -p 2001,2010 --script ./ibmi-httpadmin-audit.nse <target>
```

That tells you whether the console is reachable and how. To also learn the OS
release and whether the fix is installed, pass a profile you already hold:

```
nmap -p 2001,2010 --script ./ibmi-httpadmin-audit.nse \
  --script-args ibmi-httpadmin-audit.user=JSMITH,ibmi-httpadmin-audit.pass=... <target>
```

Without credentials the patch status is reported as unknown. The script cannot
tell you the box is patched from the outside, only that it did not get to ask.

The script runs on 2001 and 2010, or on any port nmap identifies as http. For a
console moved to another port, add `-sV`. It stays silent on anything that does
not look like the IBM i console (Server header, auth realm, or page title), so a
stray web server on 2001 does not get a finding it did not earn.

Script args: `ibmi-httpadmin-audit.user`, `.pass`, and `.path` (default `/HTTPAdmin`).

## Output

```
2001/tcp open  dc
| ibmi-httpadmin-audit:
|   verdict: FINDING
|   facts:
|     server: IBM HTTP Server for i
|     os_release: V7R4M0
|     admin_fix: not installed
|   findings:
|     [FINDING] The admin console answers on cleartext port 2001 ...
|_    [FINDING] The HTTP Server Administration fix for CVE-2026-96119 is not installed ...
```

`FINDING` is something to fix or justify. `INFO` is context. The verdict is
`FINDING` if any finding is, `SECURE` otherwise. Nothing answering prints nothing,
same as any other nmap http script.

## Checks performed

- [x] Console reachable on the cleartext port (password sent in the clear over HTTP Basic)
- [x] Console reachable on the TLS port from this network
- [x] Certificate expired, not yet valid, self-signed, RSA key under 2048 bits
- [x] Server header and auth realm from an unauthenticated request
- [x] With a profile: OS release from the About page
- [x] With a profile: CVE-2026-96119 fix installed or not, with the PTF per release
- [ ] TLS protocol version (use `ssl-enum-ciphers` alongside this script for now)

## Caveats

Run against a real IBM i (pub400.com), with these results:

- The unauthenticated side works. The console answers 401 with `Server: Apache`
  and realm `HTTP Admin`, and the script recognizes that.
- The real console is not the mock. Signing in with an ordinary profile passes
  Basic auth but gets a 200 carrying `ZUI_50044`: the profile needs `*IOSYSCFG`
  and `*ALLOBJ` (or an explicit grant) to use the interface. The mock lets any
  enabled profile in. So on real hardware this check needs a profile the console
  authorizes, and the web3270 mock overstates how reachable the console is to a
  low-privilege user.
- `/HTTPAdmin/about` and its "OS release / HTTP Server Admin fix" table are the
  mock's. The real console is a session-based app and does not serve that page,
  so the version and fix read is **unconfirmed on real hardware**. The script
  reports the console's own message instead of guessing.

IBM has not published the real vulnerable parameter for CVE-2026-96119, so the
fix status can only be trusted once the real About page location is found with an
authorized profile. Run it against systems you are authorized to test, with the
ports named in your rules of engagement.

## Tests

```
./test.sh
```

Boots web3270's mock admin GUI on 2001 and 2010 (unpatched, patched, and a
non-IBM i web server) and runs the script against each. Needs nmap, node and
openssl, those two ports free, and web3270 checked out next to this repo, or
`WEB3270=/path/to/web3270/Bridge_server`.
