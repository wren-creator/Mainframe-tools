# Tools index

Each row is a standalone tool. Click into its directory for the full README.

| Tool | Target | Language | What it does | Status |
|------|--------|----------|--------------|--------|
| [ipl-auth-race](ipl-auth-race/) | z/OS, z/VM | Python | Drives an IPL and checks whether the TN3270 listener authenticates before RACF is up, or fails closed. GUI + client HTML report. | Scaffolded, needs env tuning |
| [ibmi-httpadmin-nse](ibmi-httpadmin-nse/) | IBM i | Lua (nmap NSE) | Read-only check of the HTTP Server Administration GUI on 2001/2010: exposure, cert, and (with a profile) whether the CVE-2026-96119 fix is installed. | Tested on mock only |

## Adding a tool

1. Copy `_template/` to `tools/<tool-name>/`.
2. Fill in its README: what it audits, how to run it, what each finding means.
3. Add a row to the table above.
4. Keep it self-contained. No imports from sibling tools. Shared logic that genuinely
   needs to exist goes in a small vendored file inside the tool, not a repo-wide package.
