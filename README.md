# AD Health Check

**One read-only PowerShell script that reviews an Active Directory domain from a domain controller and prints every problem as a PASS, WARN or FAIL line you can paste into a client review.**

[![CI](https://github.com/ZachGSnow/ad-health-check/actions/workflows/ci.yml/badge.svg)](https://github.com/ZachGSnow/ad-health-check/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

<!-- TODO: screenshot of a run against a lab domain (never a client run), saved as docs/screenshot.png -->

## Why

A quarterly business review needs an honest answer to "is the domain healthy?", and the
usual answer is a dcdiag run plus whatever the engineer remembers to check. The checks that
matter most drift every few months: a new critical AD DS patch, RC4 being retired in Kerberos,
an Entra Connect version deadline. This script runs the whole list in one pass, discovers
everything from AD instead of a config file, changes nothing, and ends with a summary that
maps straight onto the review agenda.

## Features

- **Discovers the estate from AD:** domain controllers, FSMO holders, sites and subnets, DNS
  and DHCP servers, member servers, certificate authorities and Entra Connect servers.
  Nothing is hard-coded and there is no config file.
- **22 sections:** DC health (services, disks, uptime, patch level, certificates), dcdiag,
  replication, SYSVOL/DFSR, time, DNS (SRV records, forwarders, scavenging), DHCP (scopes,
  failover), AD backups, new accounts, privileged access, account hygiene, password policy and
  LAPS, Group Policy (including passwords in Group Policy Preferences), OS lifecycle, PKI and
  Entra Connect, DC hardening, Kerberos encryption, directory permissions, member servers,
  recurring event log issues and a summary.
- **Security checks that move with Microsoft's schedule:**
  - Patch level by OS build against the October 2026 AD DS update (CVE-2026-70229).
  - LDAP signing and channel binding, NTLMv1 use, SMBv1, Print Spooler and audit policy.
  - Kerberos RC4 retirement (KB5073381): accounts limited to old ciphers, service accounts
    without AES keys, and the KDC's RC4 audit events.
  - AD CS escalation paths ESC1-4, ESC6, ESC8, ESC9, ESC11 and ESC15-16, plus ESC17 (a
    community-defined path, not a Microsoft one).
  - DCSync rights, dangerous ACLs on key objects, unconstrained delegation and SID history.
  - Entra Connect version and application-based authentication ahead of the 2027-04-07
    deadline.
- **All dated facts in one block.** Every patch build, deadline and support date sits in
  `$Baseline` at the top of the script, and the run reminds you when it has not been reviewed
  for 120 days.
- **Readable after copy and paste.** Every line carries a text tag, and flagged table rows are
  marked `!!` (fail) or `!` (warn) in the margin, so the report still works in a ticket or
  an email.
- **Bounded run time.** Remote servers are queried over WinRM with a connection pre-check and a
  per-server time limit, and native tools run with a timeout, so one hung server cannot stall
  the run.

## Quick start

On a domain controller, in an elevated PowerShell session, signed in as a Domain Admin:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Invoke-ADHealthCheck.ps1
```

Only the problems, without contacting member servers:

```powershell
.\Invoke-ADHealthCheck.ps1 -IssuesOnly -SkipMemberServers
```

The script writes to the console only. To keep the report, use a transcript:

```powershell
Start-Transcript -Path .\ad-health.txt
.\Invoke-ADHealthCheck.ps1
Stop-Transcript
```

**Requirements**

- Windows PowerShell 5.1 or PowerShell 7, run as a `.ps1` file (not pasted into a console).
- The ActiveDirectory module. DnsServer, DhcpServer and GroupPolicy are used when present.
- WinRM (TCP 5985) from the DC to the other DCs, DHCP servers, CAs, Entra Connect servers and
  member servers.
- An English-language OS on the DCs: w32tm, dcdiag and dfsrmig output is parsed in English.

## Configuration

Parameters only. There is no config file.

| Parameter | Default | Meaning |
|---|---|---|
| `-NewAccountDays` | 90 | Look-back for the new user accounts list |
| `-StaleDays` | 90 | No logon in this many days counts as stale |
| `-EventDays` | 7 | Event log look-back |
| `-ScopeWarnPct` / `-ScopeFailPct` | 80 / 95 | DHCP scope utilisation thresholds |
| `-RemoteTimeoutSec` | 300 | Longest wait for any one remote server |
| `-IssuesOnly` | off | Print only WARN and FAIL lines plus the summary |
| `-SkipMemberServers` | off | Skip the member server section |

Patch builds, support dates and other dated thresholds live in `$Baseline` at the top of the
script. Review them when the run says they are old.

## How it works

1. Reads the forest, domain, DCs, FSMO roles, sites and the rest of the estate from AD.
2. Runs a self-contained collector script block on every DC (locally for the DC it runs on,
   over WinRM for the others). The collectors only read: CIM, the registry, event logs, the
   certificate store and `w32tm /query` / `auditpol /get` output.
3. Runs read-only tools from the DC it is on: `dcdiag /e /q`, `repadmin /showrepl` and
   `/replsummary`, `dfsrmig /getglobalstate` and `certutil -getreg`.
4. Prints each section as it goes, then a summary of every WARN and FAIL and a short list of
   review items (recurring issues, new accounts, admin-level access).

**What it leaves behind.** It makes no configuration changes, but it is not invisible: every
server it queries logs a WinRM logon (events 4624/4672), it pings and probes servers across the
estate, and it sends one DNS query for `www.microsoft.com` to each DNS forwarder. EDR tools
may flag the DCSync and AD CS reads. Tell the client's security team before you run it.

**The output is confidential.** It names the domain, servers, IP addresses, accounts and the
Entra tenant. Handle the transcript like any other client data.

## Testing

```powershell
Install-Module Pester -RequiredVersion 6.2.0 -Scope CurrentUser -Force -SkipPublisherCheck
.\tests\run-tests.ps1
```

68 Pester tests run in CI on Windows PowerShell 5.1 and PowerShell 7. They never run the
health check itself; they load its functions from the parsed file and check:

- OS support decisions, the patch-level verdict, trust delegation bits, ACL rights, table
  output and the date and name helpers.
- That the script parses, is plain ASCII and has help for every parameter.
- That it is read-only: every command it calls is on a reviewed list, native tools only get
  read-only arguments, and nothing writes through .NET.
- That each remote collector is self-contained, so it does not break when it runs on another
  server.
- That no top-level variable reuses the name of the script's own state (`$counts` is
  `$script:Counts` at the top level; that clash stopped 2.1.0 after section 5).

**Verified and not verified**

- Version 2.0.0 was run end to end against a production domain during a client review.
- Version 2.1.1 ran end to end against a production domain on 2026-11-16: a single-domain
  forest with two Windows Server 2022 DCs, seven member servers and Entra Connect, in about four
  minutes. (2.1.0 stopped after section 5 on the variable clash fixed in 2.1.1.)
- Exercised by that run: patch level by OS build, Windows 11 and Server 2016 support dates,
  member-server lines in the summary, the Entra Connect path read from the service, the cap on
  account-creation events and the DCSync verdicts.
- Not yet exercised on a live domain: WARN instead of FAIL when a child domain's DC list cannot
  be read, the child-domain PDC time source, the Server 2025 LDAP signing note and the trust
  delegation bit (that domain has one domain, 2022 DCs and no trusts). Their logic is unit
  tested where it is a separate function.
- Version 2.1.2 fixes what the review of that run found. Unit tested: the DCSync hint for
  Exchange groups, NTLMv1 reported as INFO when the Security log is too short, and repeated
  dcdiag events collapsed. Parse-checked only: "unknown" instead of "never" for a member
  server's patch date, a WARN when the last Entra Connect sync run cannot be read, unique
  member counts for privileged groups and the PASS total in the summary.
- Dated values were checked against Microsoft's pages on 2026-11-14: the October 2026 build
  floors (Windows Server release information), the Windows 11 servicing dates (Windows 11
  release information), the trustAttributes bits (MS-ADTS), and the RC4 and Entra Connect
  dates (KB5073381, Entra Connect version history).
- Not covered: DCs with a non-English display language, the Entra Connect last-run time
  comparison when the server's time zone is not UTC, and LAPS coverage for computers that
  back up to Entra ID only (they count as missing; the run says so).

## License

[MIT](LICENSE) (c) Zach Snow
