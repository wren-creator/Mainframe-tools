local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local base64 = require "base64"
local sslcert = require "sslcert"
local datetime = require "datetime"

description = [[
Read-only exposure check for the IBM i HTTP Server Administration GUI (IBM
Web Administration for i, the ADMIN instance on 2001 plain and 2010 TLS).

It answers what a defender asks about that console: is it reachable from
here, does it take sign-in over cleartext HTTP, what does the TLS
certificate look like, and what does an unauthenticated request give away.
If you hand it a profile you already hold, it also reads the About page and
reports the OS release and whether the HTTP Server Admin fix for
CVE-2026-96119 (the authenticated remote code execution) is installed.

It sends GETs only. It never submits a form, never touches the Create HTTP
Server page, never executes anything, and tries no credential beyond the one
pair you pass. A missing fix is reported from what the box says about
itself, not by exploiting it. This is a port of the HTTP Admin GUI Audit
probe in web3270, and only checks what that probe checks.

Without credentials the patch status stays unknown, and the output says so.
]]

---
-- @usage
-- nmap -p 2001,2010 --script ibmi-httpadmin-audit <target>
-- nmap -p 2001,2010 --script ibmi-httpadmin-audit \
--   --script-args ibmi-httpadmin-audit.user=JSMITH,ibmi-httpadmin-audit.pass=... <target>
--
-- @args ibmi-httpadmin-audit.user  IBM i profile for the About page read. Optional.
-- @args ibmi-httpadmin-audit.pass  Its password. Optional, needs user.
-- @args ibmi-httpadmin-audit.path  Console path to probe. Default /HTTPAdmin
--
-- @output
-- PORT     STATE SERVICE
-- 2001/tcp open  http
-- | ibmi-httpadmin-audit:
-- |   verdict: FINDING
-- |   facts:
-- |     server: IBM HTTP Server for i
-- |     os_release: V7R4M0
-- |     admin_fix: not installed
-- |   findings:
-- |     [FINDING] The admin console answers on cleartext port 2001 ...
-- |_    [FINDING] The HTTP Server Administration fix for CVE-2026-96119 is not installed ...

author = "Britley Hoff"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery", "version"}

portrule = shortport.port_or_service({2001, 2010}, {"http", "https", "ssl/http"})

local PTFS = "SJ11641 7.3, SJ11643 7.4, SJ11644 7.5, SJ11645 7.6"

local function is_tls(port)
  return port.version and port.version.service_tunnel == "ssl"
    or port.number == 2010 or shortport.ssl(nil, port)
end

-- Same checks as certFindings() in web3270: expired, not yet valid,
-- self-signed, RSA below 2048. An EC key is judged by the RSA rule nowhere.
local function cert_findings(host, port, add)
  local ok, status, cert = pcall(sslcert.getCertificate, host, port)
  if not ok or not status or not cert then return end

  local now = os.time()
  local nb, na = cert.validity and cert.validity.notBefore, cert.validity and cert.validity.notAfter
  if na and type(na) == "table" then
    local t = datetime.date_to_timestamp(na, 0)
    if t and t < now then add("FINDING", "Certificate expired " .. datetime.format_timestamp(t, 0) .. ".") end
  end
  if nb and type(nb) == "table" then
    local t = datetime.date_to_timestamp(nb, 0)
    if t and t > now then add("FINDING", "Certificate is not valid until " .. datetime.format_timestamp(t, 0) .. ".") end
  end

  local function dn(t)
    if type(t) ~= "table" then return "" end
    local parts = {}
    for k, v in pairs(t) do parts[#parts + 1] = tostring(k) .. "=" .. tostring(v) end
    table.sort(parts)
    return table.concat(parts, ",")
  end
  if cert.subject and cert.issuer and dn(cert.subject) == dn(cert.issuer) then
    add("INFO", "Certificate is self-signed, so clients cannot verify the console they are signing in to.")
  end

  local pk = cert.pubkey
  if pk and pk.type == "rsa" and pk.bits and tonumber(pk.bits) < 2048 then
    add("FINDING", ("Certificate key is %d bits, below 2048."):format(tonumber(pk.bits)))
  end
end

local function parse_about(body)
  local level = body:match("OS release</th><td>([^<]+)<")
  local fix = body:match("HTTP Server Admin fix</th><td>([^<]+)<")
  return level and level:gsub("^%s+", ""):gsub("%s+$", ""),
         fix and fix:gsub("^%s+", ""):gsub("%s+$", "")
end

action = function(host, port)
  local path = stdnse.get_script_args("ibmi-httpadmin-audit.path") or "/HTTPAdmin"
  local user = stdnse.get_script_args("ibmi-httpadmin-audit.user")
  local pass = stdnse.get_script_args("ibmi-httpadmin-audit.pass")
  local tls = is_tls(port)

  local findings, facts = {}, stdnse.output_table()
  local function add(sev, text) findings[#findings + 1] = ("[%s] %s"):format(sev, text) end
  local has_finding = false
  local function finding(text) has_finding = true; add("FINDING", text) end

  local resp = http.get(host, port, path, {
    header = {["User-Agent"] = "nmap-ibmi-httpadmin-audit"},
    bypass_cache = true,
  })
  if not resp or not resp.status then
    return nil  -- nothing answered here, stay quiet like any other http script
  end

  if tls then
    finding(("The admin console is reachable on TLS port %d from this network. It should only be reachable from admin workstations."):format(port.number))
    cert_findings(host, port, function(sev, text)
      if sev == "FINDING" then has_finding = true end
      add(sev, text)
    end)
  else
    finding(("The admin console answers on cleartext port %d from this network. Sign-in over it sends the IBM i password in the clear (HTTP Basic)."):format(port.number))
  end

  local server = resp.header and resp.header["server"]
  if server then
    facts.server = server
    add("INFO", ('Unauthenticated response identifies the server as "%s".'):format(server))
  end
  local realm = resp.header and resp.header["www-authenticate"]
  if realm then facts.auth = realm end

  -- Only treat it as the IBM i console when it looks like one. A random web
  -- server on 2001 should not get a finding it did not earn.
  -- A real IBM i answers 401 with "Server: Apache" and realm "HTTP Admin"
  -- (seen on pub400.com), while the web3270 mock says "IBM HTTP Server for
  -- i". Accept both. The realm is the reliable tell, the Server header is not.
  local looks_ibmi = (server and server:find("IBM HTTP Server", 1, true))
    or (realm and realm:find("HTTP Admin", 1, true))
    or (realm and realm:find("HTTP Server Administration", 1, true))
    or (resp.body and resp.body:find("IBM Web Administration for i", 1, true))
  if not looks_ibmi then
    return nil
  end

  if user and pass then
    local about = http.get(host, port, path .. "/about", {
      header = {
        ["User-Agent"] = "nmap-ibmi-httpadmin-audit",
        ["Authorization"] = "Basic " .. base64.enc(user .. ":" .. pass),
      },
      bypass_cache = true,
    })
    if about and about.status == 200 then
      local level, fix = parse_about(about.body or "")
      facts.os_release = level
      facts.admin_fix = fix
      if level then add("INFO", ("About page reports OS release %s."):format(level)) end
      if fix and fix:lower():find("not installed", 1, true) then
        finding("The HTTP Server Administration fix for CVE-2026-96119 is not installed. Apply the PTF for this release (" .. PTFS .. "), or upgrade if the release is no longer supported.")
      elseif fix then
        add("INFO", ("HTTP Server Administration fix reported as %s."):format(fix))
      else
        add("INFO", "About page did not report a fix status, so patch level is unknown.")
      end
    elseif about and about.status then
      -- A real IBM i says why it refused ("password expired", "authentication
      -- failed"), and the fix for each is different, so pass the reason on.
      local why = (about.body or ""):match("</H1>%s*(.-)%s*</[Bb][Oo][Dd][Yy]>")
      why = why and why:gsub("%s+", " ")
      add("INFO", ("About page returned HTTP %d for the supplied profile%s, so version and fix status could not be read."):format(about.status, why and why ~= "" and (' ("' .. why .. '")') or ""))
    else
      add("INFO", "Could not read the About page.")
    end
  else
    facts.admin_fix = "unknown (no credentials supplied)"
  end

  local out = stdnse.output_table()
  out.verdict = has_finding and "FINDING" or "SECURE"
  out.facts = facts
  out.findings = findings
  return out
end
