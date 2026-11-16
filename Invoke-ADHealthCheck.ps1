<#
.SYNOPSIS
    Read-only Active Directory / domain health check for MSP client reviews.

.DESCRIPTION
    Run on a domain controller, elevated, as a Domain Admin. Discovers DCs, FSMO holders,
    DNS servers, DHCP servers, member servers, certificate authorities and Entra Connect
    from AD itself - nothing is hard-coded. Makes no configuration changes: it only reads AD,
    the registry, event logs and tool output (it does leave normal WinRM logon events on the
    servers it queries). All output goes to the console with [PASS]/[WARN]/[FAIL]/[INFO] tags
    so the report still reads correctly after copy/paste.

    Sections:
       1  Environment overview        12  Account hygiene
       2  Domain controller health    13  Password policy & LAPS
       3  dcdiag                      14  Group Policy
       4  AD replication              15  OS lifecycle
       5  SYSVOL / DFSR               16  PKI & Entra Connect
       6  Time / NTP                  17  DC security hardening
       7  DNS                         18  Kerberos encryption (RC4 retirement)
       8  DHCP                        19  Directory permissions & delegation
       9  AD backups                  20  Member servers
      10  New user accounts           21  Recurring event log issues
      11  Privileged access review    22  Summary

.PARAMETER NewAccountDays
    Look-back for the new user accounts list (section 10). Default 90.

.PARAMETER StaleDays
    An enabled account or computer with no logon in this many days counts as stale. Default 90.

.PARAMETER EventDays
    Event log look-back for the recurring-issue and LDAP checks. Default 7.

.PARAMETER ScopeWarnPct
    DHCP scope utilisation that raises a WARN. Default 80.

.PARAMETER ScopeFailPct
    DHCP scope utilisation that raises a FAIL. Default 95.

.PARAMETER RemoteTimeoutSec
    Longest time to wait for any one remote server before moving on. Default 300.

.PARAMETER IssuesOnly
    Prints only WARN and FAIL lines (with the section they belong to) and the summary.

.PARAMETER SkipMemberServers
    Skips the member server collection (section 20).

.EXAMPLE
    .\Invoke-ADHealthCheck.ps1
    Full report for the domain of the DC it runs on.

.EXAMPLE
    .\Invoke-ADHealthCheck.ps1 -IssuesOnly -SkipMemberServers
    Only the WARN and FAIL lines plus the summary, without contacting member servers.

.EXAMPLE
    Start-Transcript -Path .\ad-health.txt; .\Invoke-ADHealthCheck.ps1; Stop-Transcript
    Saves the report to a text file. The script writes to the console only, so redirecting
    its output with > captures nothing; use a transcript instead.

.NOTES
    PowerShell 5.1+. Requires the ActiveDirectory module. Uses DnsServer, DhcpServer and
    GroupPolicy modules when present (DHCP data is collected on the DHCP server itself).
    Remote DCs, DHCP servers and member servers are queried over WinRM (TCP 5985).
    Run it as a .ps1 file; pasting it into a console is not supported.

    The output of w32tm, dcdiag and dfsrmig is parsed in English. On a DC with another
    display language some of those checks can be wrong; review sections 3, 5 and 6 by hand.

    The output names the domain, servers, accounts and tenant. Treat it as confidential.

    Reading the console: FAIL lines carry a red badge and WARN lines a yellow badge.
    Table rows that need attention are coloured and marked "!!" (fail) or "!" (warn) in the
    left margin. PASS lines are dimmed so problems stand out.

.LINK
    https://github.com/ZachGSnow/ad-health-check
#>
#Requires -Version 5.1
#Requires -RunAsAdministrator
#Requires -Modules ActiveDirectory
[CmdletBinding()]
param(
    [int]$NewAccountDays   = 90,   # "accounts added over the last 3 months"
    [int]$StaleDays        = 90,   # no logon in this many days = stale
    [int]$EventDays        = 7,    # event log look-back
    [int]$ScopeWarnPct     = 80,   # DHCP scope utilisation warning
    [int]$ScopeFailPct     = 95,   # DHCP scope utilisation failure
    [int]$RemoteTimeoutSec = 300,  # per remote server
    [switch]$IssuesOnly,
    [switch]$SkipMemberServers
)

$ScriptVersion = '2.1.2'

# Dated baselines. Microsoft moves these; review them when the script warns that they are old.
$Baseline = @{
    Reviewed             = [datetime]'2026-11-14'
    MinDcPatchDate       = [datetime]'2026-10-13'   # October 2026 security update (CVE-2026-70229, AD DS)
    # Lowest OS build (build -> revision) that contains the October 2026 security update.
    # 2016 KB5126868, 2019 KB5126651, 2022 KB5126655, 2025 KB5126646.
    MinDcBuild           = @{ 14393 = 9612; 17763 = 9376; 20348 = 5761; 26100 = 33650 }
    Rc4EnforcementDate   = [datetime]'2026-04-14'   # KDC stops issuing RC4 tickets by default (KB5073381)
    EntraConnectMin      = [version]'2.6.84.0'      # required with application-based authentication
    EntraConnectDeadline = [datetime]'2027-04-07'
    Server2016End        = [datetime]'2027-01-12'   # end of extended support
    # Windows 11 end of servicing per build (Windows 11 release information page, checked 2026-11-14;
    # 24H2 and older Home/Pro, and 23H2 and older Enterprise, are listed there as "End of updates").
    # HomePro covers Home, Pro, Pro Education and Pro for Workstations; Enterprise covers
    # Enterprise, Education and IoT Enterprise. LTSC editions are reported as 'Check LTSC'.
    Win11Servicing       = @{
        22000 = @{ HomePro = [datetime]'2023-10-10'; Enterprise = [datetime]'2024-10-08' }   # 21H2
        22621 = @{ HomePro = [datetime]'2024-10-08'; Enterprise = [datetime]'2025-10-14' }   # 22H2
        22631 = @{ HomePro = [datetime]'2025-11-11'; Enterprise = [datetime]'2026-11-10' }   # 23H2
        26100 = @{ HomePro = [datetime]'2026-10-13'; Enterprise = [datetime]'2027-10-12' }   # 24H2
        26200 = @{ HomePro = [datetime]'2027-10-12'; Enterprise = [datetime]'2028-10-10' }   # 25H2
        26300 = @{ HomePro = [datetime]'2028-10-10'; Enterprise = [datetime]'2029-10-09' }   # 26H2
        28000 = @{ HomePro = [datetime]'2028-03-14'; Enterprise = [datetime]'2029-03-13' }   # 26H1
    }
    SupportEndWarnDays   = 180                      # warn this long before an OS leaves support
    MaxDcUptimeDays      = 45
    MaxPatchAgeDays      = 45
}

# Elevation check, kept for hosts that ignore #Requires
$currentIdentity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'STOP: run this from an elevated PowerShell session (Run as administrator). Nothing was run.' -ForegroundColor Red
    return
}

$ErrorActionPreference = 'Stop'
$script:Now            = Get-Date
$script:Findings       = New-Object System.Collections.Generic.List[object]
$script:Counts         = @{}
$script:SectionOrder   = New-Object System.Collections.Generic.List[string]
$script:Section        = ''
$script:PendingSection = $null
$script:PendingSub     = $null
$script:SidNameCache   = @{}
$script:TSL            = 180
$script:NewUserCount = 0; $script:NewUserNeverLogon = 0
$script:PrivAccountCount = 0; $script:PrivIssueCount = 0
$script:TopRecurring = @()

# Access-right bit values (System.DirectoryServices.ActiveDirectoryRights)
$ADR = @{
    GenericAll    = 983551
    WriteDacl     = 262144
    WriteOwner    = 524288
    WriteProperty = 32
    ExtendedRight = 256
    CreateChild   = 1
}
$EmptyGuid = [guid]::Empty

#region ============================== Helpers ==============================

function Write-HeaderLines {
    # Prints the section and sub-section headings that have not been shown yet.
    # In -IssuesOnly mode a heading is held back until something under it needs printing.
    if ($script:PendingSection) {
        Write-Host ''
        Write-Host ('=' * 100) -ForegroundColor Cyan
        Write-Host "  $($script:PendingSection)" -ForegroundColor Cyan
        Write-Host ('=' * 100) -ForegroundColor Cyan
        $script:PendingSection = $null
    }
    if ($script:PendingSub) {
        Write-Host ''
        Write-Host "  --- $($script:PendingSub) ---" -ForegroundColor DarkCyan
        $script:PendingSub = $null
    }
}

function Write-Section {
    param([string]$Title)
    $script:Section        = $Title
    $script:PendingSection = $Title
    $script:PendingSub     = $null
    if (-not $script:Counts.ContainsKey($Title)) {
        $script:Counts[$Title] = @{ PASS = 0; WARN = 0; FAIL = 0 }
        $script:SectionOrder.Add($Title)
    }
    if ($IssuesOnly) { Write-Progress -Activity 'AD Health Check' -Status "Checking: $Title" }
    else { Write-HeaderLines }
}

function Write-Sub {
    param([string]$Title)
    $script:PendingSub = $Title
    if (-not $IssuesOnly) { Write-HeaderLines }
}

function Write-Status {
    param(
        [ValidateSet('PASS', 'WARN', 'FAIL', 'INFO')][string]$Status,
        [string]$Message
    )
    if ($Status -ne 'INFO' -and $script:Counts.ContainsKey($script:Section)) {
        $script:Counts[$script:Section][$Status] = $script:Counts[$script:Section][$Status] + 1
    }
    $isIssue = ($Status -eq 'WARN' -or $Status -eq 'FAIL')
    if ($isIssue) {
        $script:Findings.Add([pscustomobject]@{ Status = $Status; Section = $script:Section; Message = $Message })
    }
    if ($IssuesOnly -and -not $isIssue) { return }
    Write-HeaderLines
    if ($Status -eq 'FAIL') {
        Write-Host '  ' -NoNewline
        Write-Host '[FAIL]' -ForegroundColor White -BackgroundColor DarkRed -NoNewline
        Write-Host " $Message" -ForegroundColor Red
    } elseif ($Status -eq 'WARN') {
        Write-Host '  ' -NoNewline
        Write-Host '[WARN]' -ForegroundColor Black -BackgroundColor Yellow -NoNewline
        Write-Host " $Message" -ForegroundColor Yellow
    } elseif ($Status -eq 'PASS') {
        Write-Host "  [PASS] $Message" -ForegroundColor DarkGreen
    } else {
        Write-Host "  [INFO] $Message" -ForegroundColor Gray
    }
}

function Write-Info {
    param([string]$Message)
    if ($IssuesOnly) { return }
    Write-HeaderLines
    Write-Host "  $Message"
}

function Write-Detail {
    # Supporting detail such as raw tool output. Hidden in -IssuesOnly mode.
    param([string]$Text, [string]$Color = 'Gray')
    if ($IssuesOnly) { return }
    Write-HeaderLines
    Write-Host "    $Text" -ForegroundColor $Color
}

function Show-Table {
    # Prints objects as an aligned table. -Flag is a script block that receives one row
    # (param($row)) and returns 'FAIL', 'WARN' or nothing. Flagged rows are coloured and
    # marked in the left margin so they can be found after the text is copied elsewhere.
    param($Data, [scriptblock]$Flag)
    if ($IssuesOnly) { return }
    Write-HeaderLines
    $tblRows = @($Data | Where-Object { $_ })
    if ($tblRows.Count -eq 0) { Write-Host '    (none)' -ForegroundColor DarkGray; return }
    $tblCols  = @($tblRows[0].PSObject.Properties | ForEach-Object { $_.Name })
    $tblWidth = @{}
    foreach ($tblCol in $tblCols) { $tblWidth[$tblCol] = $tblCol.Length }
    $tblText = New-Object System.Collections.Generic.List[object]
    foreach ($tblRow in $tblRows) {
        $tblCells = @{}
        foreach ($tblCol in $tblCols) {
            $tblValue = $tblRow.$tblCol
            if ($null -eq $tblValue) { $tblCell = '' }
            elseif ($tblValue -is [datetime]) { $tblCell = $tblValue.ToString('yyyy-MM-dd HH:mm') }
            elseif ($tblValue -is [array]) { $tblCell = ($tblValue | ForEach-Object { "$_" }) -join ', ' }
            else { $tblCell = "$tblValue" }
            $tblCell = ($tblCell -replace '\s*[\r\n]+\s*', ' ').Trim()
            $tblCells[$tblCol] = $tblCell
            if ($tblCell.Length -gt $tblWidth[$tblCol]) { $tblWidth[$tblCol] = $tblCell.Length }
        }
        $tblText.Add($tblCells)
    }
    $tblHeader = ($tblCols | ForEach-Object { $_.PadRight($tblWidth[$_]) }) -join '  '
    $tblRule   = ($tblCols | ForEach-Object { '-' * $tblWidth[$_] }) -join '  '
    Write-Host ('    ' + $tblHeader.TrimEnd()) -ForegroundColor White
    Write-Host ('    ' + $tblRule) -ForegroundColor DarkGray
    for ($tblIndex = 0; $tblIndex -lt $tblRows.Count; $tblIndex++) {
        $tblCells = $tblText[$tblIndex]
        $tblLine  = (($tblCols | ForEach-Object { $tblCells[$_].PadRight($tblWidth[$_]) }) -join '  ').TrimEnd()
        $tblMark  = $null
        if ($Flag) {
            try { $tblMark = & $Flag $tblRows[$tblIndex] } catch { $tblMark = $null }
        }
        if ("$tblMark" -eq 'FAIL') { Write-Host (' !! ' + $tblLine) -ForegroundColor Red }
        elseif ("$tblMark" -eq 'WARN') { Write-Host ('  ! ' + $tblLine) -ForegroundColor Yellow }
        else { Write-Host ('    ' + $tblLine) }
    }
}

function Get-AgeDays {
    param($Date)
    if ($null -eq $Date -or $Date -isnot [datetime] -or $Date.Year -le 1601) { return $null }
    [int][math]::Floor(($script:Now - $Date).TotalDays)
}

function Format-Date {
    param($Date)
    if ($Date -is [datetime] -and $Date.Year -gt 1601) { $Date.ToString('yyyy-MM-dd') } else { 'never' }
}

function Limit-Text {
    param([string]$Text, [int]$Max = 50)
    if (-not $Text) { return '' }
    $t = ($Text -replace '\s+', ' ').Trim()
    if ($t.Length -gt $Max) { $t.Substring(0, $Max - 3) + '...' } else { $t }
}

function Get-OUPath {
    param([string]$CanonicalName)
    if (-not $CanonicalName) { return '' }
    $parts = $CanonicalName -split '/'
    if ($parts.Count -le 2) { return '/' }
    ($parts[1..($parts.Count - 2)]) -join '/'
}

function Get-DomainFromDN {
    param([string]$DN)
    (($DN -split ',') | Where-Object { $_ -like 'DC=*' } | ForEach-Object { $_.Substring(3) }) -join '.'
}

function Get-ShortName {
    param([string]$Name)
    if (-not $Name) { return '' }
    ($Name -split '\.')[0].ToLower()
}

function Get-CnFromDN {
    param([string]$DN)
    if (-not $DN) { return '' }
    (($DN -split ',')[0]) -replace '^(CN|OU)=', ''
}

function Test-Ping {
    # Two quick ICMP attempts; returns $true on the first reply
    param([string]$ComputerName, [int]$TimeoutMs = 1500)
    if (-not $ComputerName) { return $false }
    $pinger = New-Object System.Net.NetworkInformation.Ping
    try {
        foreach ($attempt in 1, 2) {
            try {
                $reply = $pinger.Send($ComputerName, $TimeoutMs)
                if ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) { return $true }
            } catch { }
        }
        return $false
    } finally { $pinger.Dispose() }
}

function Test-TcpPort {
    param([string]$ComputerName, [int]$Port, [int]$TimeoutMs = 3000)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $pending = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if (-not $pending.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { return $false }
        $client.EndConnect($pending)
        return [bool]$client.Connected
    } catch { return $false } finally { $client.Close() }
}

function Invoke-Native {
    # Runs a native executable with a time limit and returns its output as lines of text.
    # Used instead of the call operator so one hung tool cannot stall the whole run.
    param([string]$Exe, [string[]]$Arguments = @(), [int]$TimeoutSec = 120)
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName               = $Exe
    $startInfo.Arguments              = ($Arguments -join ' ')
    $startInfo.UseShellExecute        = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError  = $true
    $startInfo.CreateNoWindow         = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    try {
        [void]$process.Start()
        $stdOut = $process.StandardOutput.ReadToEndAsync()
        $stdErr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSec * 1000)) {
            try { $process.Kill() } catch { }
            throw "$Exe did not finish within $TimeoutSec seconds"
        }
        $process.WaitForExit()
        $text = "$($stdOut.Result)`n$($stdErr.Result)"
        return @($text -split "`r?`n")
    } finally { $process.Dispose() }
}

function Invoke-OnComputer {
    # Runs a script block locally when the target is this machine, otherwise over WinRM with
    # a connection pre-check and a hard time limit. Throws with a short reason on failure.
    param([string]$ComputerName, [scriptblock]$ScriptBlock, [object[]]$ArgumentList = @(), [int]$TimeoutSec = $RemoteTimeoutSec)
    if ((Get-ShortName $ComputerName) -eq $env:COMPUTERNAME.ToLower()) {
        return (& $ScriptBlock @ArgumentList)
    }
    if (-not (Test-TcpPort -ComputerName $ComputerName -Port 5985)) {
        throw "WinRM (TCP 5985) is not reachable on $ComputerName"
    }
    $session = $null
    $job     = $null
    try {
        $sessionOption = New-PSSessionOption -OpenTimeout 20000 -CancelTimeout 10000
        $session = New-PSSession -ComputerName $ComputerName -SessionOption $sessionOption -ErrorAction Stop
        $job = Invoke-Command -Session $session -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -AsJob
        $finished = Wait-Job -Job $job -Timeout $TimeoutSec
        if (-not $finished) {
            Stop-Job -Job $job -ErrorAction SilentlyContinue
            throw "no answer from $ComputerName within $TimeoutSec seconds"
        }
        return (Receive-Job -Job $job -ErrorAction Stop)
    } finally {
        if ($job) { Remove-Job -Job $job -Force -ErrorAction SilentlyContinue }
        if ($session) { Remove-PSSession -Session $session -ErrorAction SilentlyContinue }
    }
}

function ConvertTo-DateSafe {
    param([string]$Value)
    if (-not $Value -or $Value -eq '0') { return $null }
    try { [datetime]::Parse($Value) } catch { $null }
}

function Get-TimeOffset {
    # Offset (seconds) of a remote computer's clock relative to this machine
    param([string]$Target)
    $out = @()
    try { $out = Invoke-Native -Exe 'w32tm.exe' -Arguments @('/stripchart', "/computer:$Target", '/dataonly', '/samples:1') -TimeoutSec 30 } catch { }
    foreach ($line in $out) {
        if ($line -match '^\s*\d{1,2}:\d{2}:\d{2}.*?,\s*([+-]?\d+(?:[.,]\d+)?)s') {
            return [double]::Parse(($Matches[1] -replace ',', '.'), [Globalization.CultureInfo]::InvariantCulture)
        }
    }
    $null
}

function Get-OSSupport {
    param([string]$OS, [string]$Version)
    # Returns 'EOL ...' (out of support), 'EOS yyyy-MM-dd' (support ends soon), 'Supported',
    # 'Check LTSC', 'Review' or 'Unknown'. Dates come from $Baseline.
    if (-not $OS) { return 'Unknown' }
    if ($OS -match 'Server 2003|Server 2008|Server 2012|Windows XP|Windows Vista|Windows 7|Windows 8') { return 'EOL' }
    if ($OS -match 'Windows 1[01]' -and $OS -match 'LTS') { return 'Check LTSC' }
    if ($OS -match 'Windows 10') { return 'EOL (Oct 2025)' }
    if ($OS -match 'Server 2016') { return (Get-SupportState $Baseline.Server2016End) }
    if ($OS -match 'Windows 11') {
        $build = 0
        if ($Version -match '\((\d+)\)') { $build = [int]$Matches[1] }
        if ($build -le 0) { return 'Review' }
        $known = @($Baseline.Win11Servicing.Keys | Sort-Object)
        if ($build -lt $known[0]) { return 'EOL' }
        if (-not $Baseline.Win11Servicing.ContainsKey($build)) {
            if ($build -gt $known[-1]) { return 'Supported' }
            return 'Review'
        }
        $longServicing = ($OS -match 'Enterprise|Education') -and ($OS -notmatch 'Pro Education')
        $dates = $Baseline.Win11Servicing[$build]
        if ($longServicing) { return (Get-SupportState $dates.Enterprise) }
        return (Get-SupportState $dates.HomePro)
    }
    if ($OS -match 'Server 2019|Server 2022|Server 2025') { return 'Supported' }
    'Review'
}

function Get-SupportState {
    # 'EOL (yyyy-MM)' once the end date has passed, 'EOS yyyy-MM-dd' when it is near, else 'Supported'
    param([datetime]$EndDate)
    if ($script:Now -ge $EndDate) { return "EOL ($($EndDate.ToString('yyyy-MM')))" }
    if (($EndDate - $script:Now).TotalDays -le $Baseline.SupportEndWarnDays) { return "EOS $($EndDate.ToString('yyyy-MM-dd'))" }
    'Supported'
}

function Test-TgtDelegation {
    # True when a trust explicitly allows TGT delegation across it: trustAttributes bit
    # TRUST_ATTRIBUTE_CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION (0x800). Per MS-ADTS, once KB4490425
    # is installed this bit supersedes the older NO_TGT_DELEGATION bit (0x200), so 0x200 is ignored.
    param($TrustAttributes)
    if ($null -eq $TrustAttributes -or "$TrustAttributes" -notmatch '^\d+$') { return $false }
    $bits = [int64]"$TrustAttributes"
    ($bits -band 0x800) -ne 0
}

function Get-ReplicationHint {
    # The advice printed after a DCSync finding, matched to who holds the right
    param([string]$HolderName, [string]$Verdict)
    if ($Verdict -match 'server is gone') { return 'Remove the permission and the leftover sync account' }
    if ($HolderName -match 'Exchange|Organization Management') {
        return 'This is an Exchange group: confirm with whoever runs Exchange why it holds this right, and remove it if nothing needs it'
    }
    if ($Verdict -cmatch 'NOT a default') {
        return 'Remove the permission unless it is a custom Entra Connect AD DS connector account or otherwise known and needed'
    }
    'Remove the permission unless it is known and needed'
}

function Test-LogCoversWindow {
    # True when a log's oldest event is at least $Days old, so "nothing found" covers the whole window
    param($Oldest, [int]$Days)
    if ($Oldest -isnot [datetime]) { return $false }
    ($script:Now - $Oldest).TotalDays -ge $Days
}

function Compress-DcdiagOutput {
    # dcdiag /e /q prints every matching event in full, so one noisy source can fill the screen.
    # Collapses event blocks with the same ID and text into one block with a count and a time range;
    # every other line (the "failed test" lines included) is kept in order.
    param([string[]]$Lines)
    $out = New-Object System.Collections.Generic.List[string]
    $groups = New-Object System.Collections.Specialized.OrderedDictionary
    $current = $null
    $flushGroups = {
        foreach ($g in $groups.Values) {
            # The header, then when it happened (one time, or a count and range), then the event text
            $out.Add($g.Lines[0])
            if ($g.Seen -gt 1) { $out.Add("                (x$($g.Seen), first $($g.First), last $($g.Last))") }
            elseif ($g.First) { $out.Add("                Time Generated: $($g.First)") }
            for ($gi = 1; $gi -lt $g.Lines.Count; $gi++) { $out.Add($g.Lines[$gi]) }
        }
        $groups.Clear()
    }
    $closeBlock = {
        if ($null -eq $current) { return }
        $key = ($current.Body -join "`n")
        if ($groups.Contains($key)) {
            $groups[$key].Seen++
            if ($current.Time) { $groups[$key].Last = $current.Time }
        } else {
            $groups[$key] = @{ Lines = $current.Body; Seen = 1; First = $current.Time; Last = $current.Time }
        }
    }
    foreach ($line in $Lines) {
        if ($line -match '^\s*An? (error|warning) event occurred\.') {
            . $closeBlock
            $current = @{ Body = New-Object System.Collections.Generic.List[string]; Time = '' }
            $current.Body.Add($line)
        } elseif ($null -ne $current -and $line -match '^\s*Time Generated:\s*(.+?)\s*$') {
            $current.Time = ($Matches[1] -replace '\s+', ' ')
        } elseif ($null -ne $current -and $line -notmatch '^\s*\.{3,}' -and $line -notmatch '^\s*(Testing|Starting test|Doing )') {
            $current.Body.Add($line)
        } else {
            . $closeBlock
            $current = $null
            . $flushGroups
            $out.Add($line)
        }
    }
    . $closeBlock
    . $flushGroups
    $out
}

function Get-PatchVerdict {
    # Decides whether a DC has the baseline security update. Uses the OS build and revision
    # (UBR) when the build is in $Baseline.MinDcBuild; otherwise falls back to the newest
    # hotfix install date, which can only prove the update is missing, never that it is there.
    # Returns @{ Status = PASS|WARN|FAIL; Message = text }.
    param($Build, $Ubr, $LastPatch, [string]$PatchFloor)
    $buildNumber = 0; $revision = -1
    if ($null -ne $Build -and "$Build" -match '^\d+$') { $buildNumber = [int]"$Build" }
    if ($null -ne $Ubr -and "$Ubr" -match '^\d+$') { $revision = [int]"$Ubr" }
    if ($buildNumber -gt 0 -and $revision -ge 0 -and $Baseline.MinDcBuild.ContainsKey($buildNumber)) {
        $minimum = [int]$Baseline.MinDcBuild[$buildNumber]
        if ($revision -ge $minimum) {
            return @{ Status = 'PASS'; Message = "build $buildNumber.$revision includes the $PatchFloor security update (needs $buildNumber.$minimum or later)" }
        }
        return @{ Status = 'FAIL'; Message = "build $buildNumber.$revision is older than $buildNumber.$minimum - missing the $PatchFloor security update for AD DS (CVE-2026-70229)" }
    }
    if ($LastPatch -is [datetime] -and $LastPatch -lt $Baseline.MinDcPatchDate) {
        return @{ Status = 'FAIL'; Message = "newest update was installed $(Format-Date $LastPatch) - missing the $PatchFloor security update for AD DS (CVE-2026-70229)" }
    }
    $buildText = 'unknown'
    if ($buildNumber -gt 0) { $buildText = "$buildNumber.$revision" }
    return @{ Status = 'WARN'; Message = "no baseline build for this OS (build $buildText) - confirm the $PatchFloor security update for AD DS (CVE-2026-70229) is installed" }
}

function Resolve-SidName {
    # SID string -> DOMAIN\name (cached). Returns the SID itself when it cannot be resolved.
    param([string]$Sid)
    if (-not $Sid) { return '' }
    if ($script:SidNameCache.ContainsKey($Sid)) { return $script:SidNameCache[$Sid] }
    $resolved = $Sid
    try {
        $sidObject = New-Object System.Security.Principal.SecurityIdentifier($Sid)
        $resolved = $sidObject.Translate([System.Security.Principal.NTAccount]).Value
    } catch { }
    $script:SidNameCache[$Sid] = $resolved
    return $resolved
}

function Get-SidClass {
    # 'Safe'   = built-in administrative or system principal, or a current admin account
    # 'Unsafe' = a broad group that every user or computer belongs to
    # 'Other'  = anything else (a named user or group that is not an administrator)
    param([string]$Sid)
    if ($script:SafeSids.Contains($Sid) -or $script:AdminSids.Contains($Sid)) { return 'Safe' }
    if ($script:UnsafeSids.Contains($Sid)) { return 'Unsafe' }
    return 'Other'
}

function Get-AdAcl {
    # Owner and access rules of an AD object, with every identity returned as a SID string
    param([string]$DN, [string]$Server)
    $adObject = Get-ADObject -Identity $DN -Server $Server -Properties nTSecurityDescriptor
    $descriptor = $adObject.nTSecurityDescriptor
    $sidType = [System.Security.Principal.SecurityIdentifier]
    [pscustomobject]@{
        DN    = $DN
        Owner = "$($descriptor.GetOwner($sidType).Value)"
        Rules = @($descriptor.GetAccessRules($true, $true, $sidType))
    }
}

function Get-DangerousRights {
    # Names the high-impact rights one access rule grants (empty when it grants none).
    # Property-specific write rules are ignored on purpose: AD has dozens of those by default.
    param($Rule)
    $granted = @()
    if ("$($Rule.AccessControlType)" -ne 'Allow') { return $granted }
    $rights = [int]$Rule.ActiveDirectoryRights
    $wholeObject = ($Rule.ObjectType -eq $EmptyGuid)
    if (($rights -band $ADR.GenericAll) -eq $ADR.GenericAll) {
        $granted += 'full control'
    } else {
        if (($rights -band $ADR.WriteDacl) -ne 0) { $granted += 'change permissions' }
        if (($rights -band $ADR.WriteOwner) -ne 0) { $granted += 'take ownership' }
        if ((($rights -band $ADR.WriteProperty) -ne 0) -and $wholeObject) { $granted += 'write all properties' }
        if ((($rights -band $ADR.ExtendedRight) -ne 0) -and $wholeObject) { $granted += 'all extended rights' }
    }
    return $granted
}

function Test-AclTarget {
    # Reports non-admin principals that hold high-impact rights on one AD object.
    # Returns the number of findings so the caller can print a PASS when there are none.
    param([string]$DN, [string]$Label, [switch]$IncludeInherited, [switch]$CheckOwner)
    $found = 0
    try { $acl = Get-AdAcl -DN $DN -Server $PDC } catch {
        Write-Status WARN "$($Label): could not read its permissions - $($_.Exception.Message)"
        return 1
    }
    $byPrincipal = @{}
    foreach ($rule in $acl.Rules) {
        if ($rule.IsInherited -and -not $IncludeInherited) { continue }
        $sid = "$($rule.IdentityReference.Value)"
        $class = Get-SidClass $sid
        if ($class -eq 'Safe') { continue }
        $rights = @(Get-DangerousRights $rule)
        if ($rights.Count -eq 0) { continue }
        # Rules that only apply to objects underneath are still reported, and labelled as such
        $scopeNote = ''
        if ("$($rule.InheritanceType)" -eq 'Descendents' -or "$($rule.InheritanceType)" -eq 'Children') { $scopeNote = ' on child objects' }
        if (-not $byPrincipal.ContainsKey($sid)) { $byPrincipal[$sid] = New-Object System.Collections.Generic.List[string] }
        foreach ($right in $rights) {
            $rightText = $right + $scopeNote
            if (-not $byPrincipal[$sid].Contains($rightText)) { $byPrincipal[$sid].Add($rightText) }
        }
    }
    foreach ($sid in @($byPrincipal.Keys)) {
        $found++
        $severity = 'WARN'
        if ((Get-SidClass $sid) -eq 'Unsafe') { $severity = 'FAIL' }
        $principalName = Resolve-SidName $sid
        $hint = ''
        if ($principalName -match 'Exchange') { $hint = ' (set by Exchange setup; a well-known escalation path if Exchange servers are compromised)' }
        Write-Status $severity "$($Label): '$principalName' has $($byPrincipal[$sid] -join ', ')$hint"
    }
    if ($CheckOwner -and $acl.Owner) {
        $ownerClass = Get-SidClass $acl.Owner
        if ($ownerClass -ne 'Safe') {
            $found++
            $severity = 'WARN'
            if ($ownerClass -eq 'Unsafe') { $severity = 'FAIL' }
            Write-Status $severity "$($Label): owned by '$(Resolve-SidName $acl.Owner)' - the owner can rewrite its permissions (expected: Domain Admins)"
        }
    }
    return $found
}

#endregion

#region ============================== Remote collectors ==============================

# Runs ON each DC (locally or via WinRM). Read-only. Returns plain values only.
$DCCollector = {
    param([int]$EventDays, [int]$NewAccountDays)
    $ErrorActionPreference = 'SilentlyContinue'
    $r = [ordered]@{}
    $since = (Get-Date).AddDays(-$EventDays)

    function Get-RegValue {
        param([string]$Path, [string]$Name)
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($null -ne $item) { return $item.$Name }
        return $null
    }

    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    $r.ComputerName = $env:COMPUTERNAME
    $r.OS           = $os.Caption
    $r.LastBoot     = $os.LastBootUpTime
    $r.Model        = "$($cs.Manufacturer) $($cs.Model)"
    $r.IsVirtual    = [bool]("$($cs.Manufacturer) $($cs.Model)" -match 'Virtual|VMware|KVM|QEMU|Xen|Nutanix|innotek|Parallels|Amazon EC2|Google Compute')

    # Memory and CPU (TotalVisibleMemorySize and FreePhysicalMemory are in KB)
    $r.RamTotalGB = $null; $r.RamFreeGB = $null; $r.RamUsedPct = $null
    if ($os.TotalVisibleMemorySize -gt 0) {
        $r.RamTotalGB = [math]::Round($os.TotalVisibleMemorySize / 1048576, 1)
        $r.RamFreeGB  = [math]::Round($os.FreePhysicalMemory / 1048576, 1)
        $r.RamUsedPct = [math]::Round(100 * ($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize, 0)
    }
    $r.CpuLoadPct = $null
    $cpu = Get-CimInstance -ClassName Win32_Processor | Measure-Object -Property LoadPercentage -Average
    if ($null -ne $cpu.Average) { $r.CpuLoadPct = [math]::Round($cpu.Average, 0) }

    # Services
    $r.Services = @(foreach ($n in 'NTDS', 'ADWS', 'Netlogon', 'Kdc', 'DNS', 'DFSR', 'W32Time', 'IsmServ') {
            $s = Get-Service -Name $n
            if ($s) { [pscustomobject]@{ Name = $n; Status = "$($s.Status)"; StartType = "$($s.StartType)" } }
            else { [pscustomobject]@{ Name = $n; Status = 'NotInstalled'; StartType = '' } }
        })

    # NTDS / SYSVOL locations and disk space on every fixed volume
    $ntds = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
    $r.NtdsDb   = $ntds.'DSA Database file'
    $r.NtdsLogs = $ntds.'Database log files path'
    $r.Sysvol   = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters').SysVol
    $r.NtdsDbGB = $null
    if ($r.NtdsDb) {
        $dbFile = Get-Item -LiteralPath $r.NtdsDb
        if ($dbFile) { $r.NtdsDbGB = [math]::Round($dbFile.Length / 1073741824, 2) }
    }
    $r.Disks = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' | Where-Object { $_.Size -gt 0 } | ForEach-Object {
            $d = "$($_.DeviceID)".ToUpper()
            $holds = @()
            if ($d -eq "$($env:SystemDrive)".ToUpper()) { $holds += 'OS' }
            if ($r.NtdsDb -and $r.NtdsDb.ToUpper().StartsWith($d)) { $holds += 'NTDS DB' }
            if ($r.NtdsLogs -and $r.NtdsLogs.ToUpper().StartsWith($d)) { $holds += 'NTDS logs' }
            if ($r.Sysvol -and $r.Sysvol.ToUpper().StartsWith($d)) { $holds += 'SYSVOL' }
            [pscustomobject]@{
                Drive   = $d
                SizeGB  = [math]::Round($_.Size / 1073741824, 1)
                FreeGB  = [math]::Round($_.FreeSpace / 1073741824, 1)
                FreePct = [math]::Round(100 * $_.FreeSpace / $_.Size, 1)
                Holds   = $holds -join ', '
            }
        })

    # Shares
    $r.Shares = @(Get-CimInstance -ClassName Win32_Share | Where-Object { $_.Name -eq 'SYSVOL' -or $_.Name -eq 'NETLOGON' } | ForEach-Object { $_.Name })

    # DFSR SYSVOL state + key DFSR events
    $rf = Get-CimInstance -Namespace 'root/microsoftdfs' -ClassName DfsrReplicatedFolderInfo -Filter "ReplicatedFolderName='SYSVOL Share'"
    $r.SysvolDfsrState = $null
    if ($rf) { $r.SysvolDfsrState = [int]@($rf)[0].State }
    $dfsrEv = @(Get-WinEvent -FilterHashtable @{ LogName = 'DFS Replication'; Id = 2213, 2214, 4012 } -MaxEvents 200)
    $r.Last2213 = ($dfsrEv | Where-Object { $_.Id -eq 2213 } | Select-Object -First 1).TimeCreated
    $r.Last2214 = ($dfsrEv | Where-Object { $_.Id -eq 2214 } | Select-Object -First 1).TimeCreated
    $r.Last4012 = ($dfsrEv | Where-Object { $_.Id -eq 4012 } | Select-Object -First 1).TimeCreated

    # Time service
    $tp = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters'
    $r.TimeType    = $tp.Type
    $r.NtpServer   = $tp.NtpServer
    # Prefer the effective config (includes GPO-applied time settings)
    $cfg = (& w32tm.exe /query /configuration 2>$null) | Out-String
    if ($cfg -match '(?m)^\s*Type:\s*(\S+)') { $r.TimeType = $Matches[1] }
    if ($cfg -match '(?m)^\s*NtpServer:\s*(.+?)\s*\((Local|Policy)\)') { $r.NtpServer = "$($Matches[1]) [$($Matches[2])]" }
    $r.VMICEnabled = [int](Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\VMICTimeProvider').Enabled
    $r.TimeSource  = ((& w32tm.exe /query /source 2>$null) | Out-String).Trim()
    $st = (& w32tm.exe /query /status 2>$null) | Out-String
    $r.LeapIndicator = $null; $r.Stratum = $null; $r.LastTimeSync = $null
    if ($st -match 'Leap Indicator:\s*(\d)') { $r.LeapIndicator = [int]$Matches[1] }
    if ($st -match 'Stratum:\s*(\d+)') { $r.Stratum = [int]$Matches[1] }
    if ($st -match 'Last Successful Sync Time:\s*([^\r\n]+)') {
        try { $r.LastTimeSync = [datetime]::Parse($Matches[1].Trim()) } catch { }
    }

    # Patching / reboot
    $hf = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
    $r.LastPatch     = $hf.InstalledOn
    $r.LastPatchKB   = $hf.HotFixID
    $ntVersion       = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $r.OsBuild       = $ntVersion.CurrentBuild
    $r.OsUbr         = $ntVersion.UBR
    $r.PendingReboot = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
                       (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')

    # Network / DNS client
    $r.IPs = @(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' } | ForEach-Object { $_.IPAddress })
    $r.DnsClient = @(Get-DnsClientServerAddress -AddressFamily IPv4 |
            Where-Object { $_.ServerAddresses -and $_.InterfaceAlias -notmatch 'Loopback|isatap|Teredo' } |
            ForEach-Object { [pscustomobject]@{ Interface = $_.InterfaceAlias; Servers = @($_.ServerAddresses) } })

    # Server auth / KDC certs
    $r.Certs = @(Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {
            $ekus = @($_.EnhancedKeyUsageList | ForEach-Object { $_.ObjectId })
            ($ekus -contains '1.3.6.1.5.5.7.3.1') -or ($ekus -contains '1.3.6.1.5.2.3.5')
        } | ForEach-Object { [pscustomobject]@{ Subject = $_.Subject; NotAfter = $_.NotAfter; Thumbprint = $_.Thumbprint } })

    # ---- Security configuration (registry values are read, never written) ----
    $ntdsKey     = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
    $lsaKey      = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $msvKey      = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
    $netlogonKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
    $kerbPolKey  = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
    $r.LdapServerIntegrity    = Get-RegValue $ntdsKey 'LDAPServerIntegrity'
    $r.LdapChannelBinding     = Get-RegValue $ntdsKey 'LdapEnforceChannelBinding'
    $r.LmCompatibilityLevel   = Get-RegValue $lsaKey 'LmCompatibilityLevel'
    $r.DsrmAdminLogonBehavior = Get-RegValue $lsaKey 'DsrmAdminLogonBehavior'
    $r.LegacyAuditOverride    = Get-RegValue $lsaKey 'SCENoApplyLegacyAuditPolicy'
    $r.BlockNtlmv1SSO         = Get-RegValue $msvKey 'BlockNtlmv1SSO'
    $r.AuditReceivingNtlm     = Get-RegValue $msvKey 'AuditReceivingNTLMTraffic'
    $r.AuditNtlmInDomain      = Get-RegValue $netlogonKey 'AuditNTLMInDomain'
    $r.NetlogonAllowList      = [bool](Get-RegValue $netlogonKey 'VulnerableChannelAllowList')
    $r.KdcDefaultEncTypes     = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' 'DefaultDomainSupportedEncTypes'
    $r.KerbPolicyEncTypes     = Get-RegValue $kerbPolKey 'SupportedEncryptionTypes'
    $r.Rc4Phase               = Get-RegValue $kerbPolKey 'RC4DefaultDisablementPhase'

    # Print Spooler
    $spooler = Get-Service -Name Spooler
    $r.SpoolerStatus  = "$($spooler.Status)"
    $r.SpoolerStart   = "$($spooler.StartType)"
    $r.SharedPrinters = @(Get-Printer | Where-Object { $_.Shared }).Count

    # SMB server settings
    $smb = Get-SmbServerConfiguration
    $r.Smb1Enabled       = $smb.EnableSMB1Protocol
    $r.SmbRequireSigning = $smb.RequireSecuritySignature
    $r.Smb1Feature       = "$((Get-WindowsFeature -Name FS-SMB1).InstallState)"

    # Advanced audit policy (matched by subcategory GUID in the main script)
    $auditRows = @(& auditpol.exe /get /category:* /r 2>$null | Where-Object { $_ -and "$_".Trim() } | ConvertFrom-Csv)
    $r.AuditPolicy = @($auditRows | ForEach-Object {
            [pscustomobject]@{ Guid = "$($_.'Subcategory GUID')".Trim('{', '}').ToUpper(); Name = "$($_.Subcategory)"; Setting = "$($_.'Inclusion Setting')" }
        })

    # Security log size, age and clear events
    $secLog = Get-WinEvent -ListLog Security
    $r.SecurityLogMaxMB = $null
    if ($secLog) { $r.SecurityLogMaxMB = [math]::Round($secLog.MaximumSizeInBytes / 1048576, 0) }
    $r.SecurityOldest = (Get-WinEvent -LogName Security -MaxEvents 1 -Oldest).TimeCreated
    $r.LogCleared = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 1102; StartTime = (Get-Date).AddDays(-30) } -MaxEvents 5 | ForEach-Object { $_.TimeCreated })

    # LDAP signing / channel binding events
    $ldapEv = @(Get-WinEvent -FilterHashtable @{ LogName = 'Directory Service'; Id = 2886, 2887, 3039, 3040, 3041, 3074, 3075; StartTime = $since } -MaxEvents 500)
    $r.LdapEvents = @($ldapEv | Group-Object -Property Id | ForEach-Object { [pscustomobject]@{ Id = [int]$_.Name; Count = $_.Count } })
    $r.UnsignedBindSummary = ''
    $last2887 = $ldapEv | Where-Object { $_.Id -eq 2887 } | Sort-Object TimeCreated -Descending | Select-Object -First 1
    if ($last2887 -and $last2887.Properties.Count -ge 2) {
        $r.UnsignedBindSummary = "$($last2887.Properties[0].Value) simple binds without TLS and $($last2887.Properties[1].Value) unsigned SASL binds in the latest 24-hour summary"
    }

    # Kerberos RC4 audit events (KB5073381): System log, IDs 201-209 from the KDC
    $kdcEv = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 201, 202, 203, 204, 205, 206, 207, 208, 209; StartTime = (Get-Date).AddDays(-30) } -MaxEvents 2000 |
            Where-Object { $_.ProviderName -match 'Kdc|Kerberos-Key-Distribution' })
    $r.KdcRc4Events = @($kdcEv | Group-Object -Property Id | ForEach-Object {
            $latest = $_.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1
            $sample = ''
            if ($latest.Message) { $sample = ($latest.Message -replace '\s+', ' ').Trim() }
            if ($sample.Length -gt 300) { $sample = $sample.Substring(0, 300) }
            [pscustomobject]@{ Id = [int]$_.Name; Count = $_.Count; LastSeen = $latest.TimeCreated; Sample = $sample }
        })

    # NTLMv1 logons seen by this DC (anonymous logons excluded). The query has to read every logon event in
    # the window, so on a DC with a large Security log the window is cut to one day to keep the run short.
    $r.NtlmWindowDays = $EventDays
    if ($r.SecurityLogMaxMB -gt 1024) { $r.NtlmWindowDays = 1 }
    $lookbackMs = [int64]$r.NtlmWindowDays * 86400000
    $ntlmQuery = "*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= $lookbackMs]] and EventData[Data[@Name='LmPackageName']='NTLM V1']]"
    $v1Events = @(Get-WinEvent -LogName Security -FilterXPath $ntlmQuery -MaxEvents 200)
    $v1Sources = @(foreach ($ev in $v1Events) {
            $xml = [xml]$ev.ToXml()
            $data = @{}
            foreach ($node in $xml.Event.EventData.Data) { $data[$node.Name] = $node.'#text' }
            if ($data['TargetUserSid'] -ne 'S-1-5-7') { "$($data['TargetUserName']) from $($data['WorkstationName']) [$($data['IpAddress'])]" }
        })
    $r.NtlmV1Count = $v1Sources.Count
    $r.NtlmV1Top = @($v1Sources | Group-Object | Sort-Object Count -Descending | Select-Object -First 8 | ForEach-Object { "$($_.Name) x$($_.Count)" })

    # Event log summary. One query per provider so a provider that is missing cannot hide the others.
    $specs = @(
        @{ LogName = 'Directory Service'; Level = 1, 2, 3; StartTime = $since },
        @{ LogName = 'DFS Replication'; Level = 1, 2, 3; StartTime = $since },
        @{ LogName = 'DNS Server'; Level = 1, 2, 3; StartTime = $since },
        @{ LogName = 'System'; Level = 1, 2; StartTime = $since },
        @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Time-Service'; Level = 3; StartTime = $since },
        @{ LogName = 'System'; ProviderName = 'NETLOGON'; Level = 3; StartTime = $since },
        @{ LogName = 'System'; ProviderName = 'disk'; Level = 3; StartTime = $since },
        @{ LogName = 'System'; ProviderName = 'Ntfs'; Level = 3; StartTime = $since },
        @{ LogName = 'Application'; ProviderName = 'ESENT'; Level = 1, 2; StartTime = $since }
    )
    $events = foreach ($spec in $specs) { Get-WinEvent -FilterHashtable $spec -MaxEvents 5000 }
    $r.Events = @($events | Group-Object -Property 'LogName', 'ProviderName', 'Id' | ForEach-Object {
            $latest = $_.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1
            $msg = ''
            if ($latest.Message) { $msg = ($latest.Message -split "`r?`n")[0] }
            [pscustomobject]@{
                Log      = $latest.LogName
                Source   = $latest.ProviderName
                Id       = $latest.Id
                Level    = [int]$latest.Level
                Count    = $_.Count
                LastSeen = $latest.TimeCreated
                Message  = $msg
            }
        } | Sort-Object Count -Descending | Select-Object -First 25)

    # Security log: account creations (4720) for "who created it"
    $r.Created4720 = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4720; StartTime = (Get-Date).AddDays(-$NewAccountDays) } -MaxEvents 2000 | ForEach-Object {
            $x = [xml]$_.ToXml()
            $d = @{}
            foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
            [pscustomobject]@{ Time = $_.TimeCreated; Target = $d['TargetUserName']; By = "$($d['SubjectDomainName'])\$($d['SubjectUserName'])" }
        })

    [pscustomobject]$r
}

# Runs ON each member server over WinRM. Read-only. Returns plain values only.
$ServerCollector = {
    param([int]$EventDays)
    $ErrorActionPreference = 'SilentlyContinue'
    $r = [ordered]@{}
    $since = (Get-Date).AddDays(-$EventDays)

    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $r.ComputerName = $env:COMPUTERNAME
    $r.OS           = $os.Caption
    $r.LastBoot     = $os.LastBootUpTime

    $r.RamTotalGB = $null; $r.RamUsedPct = $null
    if ($os.TotalVisibleMemorySize -gt 0) {
        $r.RamTotalGB = [math]::Round($os.TotalVisibleMemorySize / 1048576, 1)
        $r.RamUsedPct = [math]::Round(100 * ($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize, 0)
    }
    $r.CpuLoadPct = $null
    $cpu = Get-CimInstance -ClassName Win32_Processor | Measure-Object -Property LoadPercentage -Average
    if ($null -ne $cpu.Average) { $r.CpuLoadPct = [math]::Round($cpu.Average, 0) }

    $r.Disks = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' | Where-Object { $_.Size -gt 0 } | ForEach-Object {
            [pscustomobject]@{
                Drive   = "$($_.DeviceID)".ToUpper()
                Label   = "$($_.VolumeName)"
                SizeGB  = [math]::Round($_.Size / 1073741824, 1)
                FreeGB  = [math]::Round($_.FreeSpace / 1073741824, 1)
                FreePct = [math]::Round(100 * $_.FreeSpace / $_.Size, 1)
            }
        })

    $hf = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
    $r.LastPatch     = $hf.InstalledOn
    $r.LastPatchKB   = $hf.HotFixID
    $r.PendingReboot = (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or
                       (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')

    # Automatic services that are not running (common trigger-start and updater services left out)
    $quiet = '^(gupdate|gupdatem|GoogleUpdater|edgeupdate|edgeupdatem|MicrosoftEdgeElevationService|sppsvc|RemoteRegistry|MapsBroker|TrustedInstaller|WbioSrvc|CDPSvc|BITS|DoSvc|wuauserv|UsoSvc|WaaSMedicSvc|TabletInputService|stisvc|gpsvc|ShellHWDetection|tiledatamodelsvc|clr_optimization|IaasVmProvider|dbupdate|dbupdatem|AGSService|AdobeARMservice|TieringEngineService|WdiSystemHost|smphost|CcmExec|RmSvc|KeyIso|Dnscache|NgcSvc|NgcCtnrSvc|MSDTC|DiagTrack|InstallService|StateRepository|tzautoupdate|VSS|swprv|TermService|SysMain|WinRM)'
    $r.StoppedAuto = @(Get-CimInstance -ClassName Win32_Service -Filter "StartMode='Auto' AND State<>'Running'" |
            Where-Object { $_.Name -notmatch $quiet -and $_.Name -notmatch '_[0-9a-f]{4,}$' -and -not $_.DelayedAutoStart } |
            ForEach-Object { "$($_.DisplayName)" })

    $specs = @(
        @{ LogName = 'System'; Level = 1, 2; StartTime = $since },
        @{ LogName = 'Application'; Level = 1, 2; StartTime = $since }
    )
    $events = foreach ($spec in $specs) { Get-WinEvent -FilterHashtable $spec -MaxEvents 3000 }
    $r.EventTotal = @($events).Count
    $r.Events = @($events | Group-Object -Property 'LogName', 'ProviderName', 'Id' | ForEach-Object {
            $latest = $_.Group | Sort-Object TimeCreated -Descending | Select-Object -First 1
            $msg = ''
            if ($latest.Message) { $msg = ($latest.Message -split "`r?`n")[0] }
            [pscustomobject]@{
                Log      = $latest.LogName
                Source   = $latest.ProviderName
                Id       = $latest.Id
                Count    = $_.Count
                LastSeen = $latest.TimeCreated
                Message  = $msg
            }
        } | Sort-Object Count -Descending | Select-Object -First 8)

    [pscustomobject]$r
}

# Runs ON each DHCP server. Returns plain values only.
$DhcpCollector = {
    $ErrorActionPreference = 'SilentlyContinue'
    Import-Module DhcpServer -ErrorAction Stop
    $r = [ordered]@{}
    $r.Server = $env:COMPUTERNAME
    $r.IsDC   = ((Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole -ge 4)
    $r.DnsCredUser = "$((Get-DhcpServerDnsCredential).UserName)"
    $r.ServerOpt6  = (@((Get-DhcpServerv4OptionValue | Where-Object { $_.OptionId -eq 6 } | Select-Object -First 1).Value) -join ',')
    $stats = @(Get-DhcpServerv4ScopeStatistics)
    $r.Scopes = @(foreach ($s in @(Get-DhcpServerv4Scope)) {
            $sid  = "$($s.ScopeId)"
            $st   = $stats | Where-Object { "$($_.ScopeId)" -eq $sid } | Select-Object -First 1
            $opts = @(Get-DhcpServerv4OptionValue -ScopeId $s.ScopeId)
            [pscustomobject]@{
                ScopeId      = $sid
                Name         = $s.Name
                Range        = "$($s.StartRange)-$($s.EndRange)"
                Mask         = "$($s.SubnetMask)"
                State        = "$($s.State)"
                Lease        = "$($s.LeaseDuration)"
                InUse        = [int]$st.AddressesInUse
                Free         = [int]$st.AddressesFree
                PctInUse     = [math]::Round([double]$st.PercentageInUse, 1)
                Options      = (($opts | Sort-Object OptionId | ForEach-Object { "$($_.OptionId)=$(@($_.Value) -join ',')" }) -join '; ')
                Opt6         = (@(($opts | Where-Object { $_.OptionId -eq 6 } | Select-Object -First 1).Value) -join ',')
                Exclusions   = ((@(Get-DhcpServerv4ExclusionRange -ScopeId $s.ScopeId) | ForEach-Object { "$($_.StartRange)-$($_.EndRange)" }) -join '; ')
                Reservations = @(Get-DhcpServerv4Reservation -ScopeId $s.ScopeId | ForEach-Object { ("$($_.IPAddress)|$($_.ClientId)").ToLower() })
            }
        })
    $r.Failover = @(Get-DhcpServerv4Failover | ForEach-Object {
            [pscustomobject]@{
                Name        = $_.Name
                Partner     = $_.PartnerServer
                Mode        = "$($_.Mode)"
                State       = "$($_.State)"
                Role        = "$($_.ServerRole)"
                LoadBalance = $_.LoadBalancePercent
                Scopes      = @($_.ScopeId | ForEach-Object { "$_" })
            }
        })
    [pscustomobject]$r
}

#endregion

#region ============================== Discovery / collection ==============================

$act = 'AD Health Check'
Write-Progress -Activity $act -Status 'Discovering forest and domain'
try {
    Import-Module ActiveDirectory
    $Forest  = Get-ADForest
    $Domain  = Get-ADDomain
    $RootDSE = Get-ADRootDSE
} catch {
    Write-Host "Cannot query Active Directory: $($_.Exception.Message)" -ForegroundColor Red
    return
}
$ConfigNC = $RootDSE.configurationNamingContext
$SchemaNC = $RootDSE.schemaNamingContext
$PDC      = $Domain.PDCEmulator
$DomDNS   = $Domain.DNSRoot
$DomDN    = $Domain.DistinguishedName
$DomSID   = $Domain.DomainSID.Value
$DCs      = @(Get-ADDomainController -Filter * -Server $DomDNS | Sort-Object Name)
$WritableDCs = @($DCs | Where-Object { -not $_.IsReadOnly })
try { $RootDomain = Get-ADDomain -Identity $Forest.RootDomain -Server $Forest.RootDomain } catch { $RootDomain = $Domain }
$RootSID = $RootDomain.DomainSID.Value

# All DC names in the forest (for metadata checks)
$ForestDCNames = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
$UnreachableDomains = New-Object System.Collections.Generic.List[string]
foreach ($d in $Forest.Domains) {
    try { Get-ADDomainController -Filter * -Server $d -ErrorAction Stop | ForEach-Object { [void]$ForestDCNames.Add($_.Name) } } catch { $UnreachableDomains.Add("$d") }
}
# When a domain could not be listed, "not a current DC" may only mean "in a domain we could not read"
$UnverifiedNote = ''
if ($UnreachableDomains.Count -gt 0) { $UnverifiedNote = " - could not verify: the DC list for $($UnreachableDomains -join ', ') could not be read" }
foreach ($dc in $DCs) { [void]$ForestDCNames.Add($dc.Name) }

function Get-ServerForDN {
    param([string]$DN)
    $d = Get-DomainFromDN $DN
    if ($d -ieq $DomDNS) { $PDC } else { $d }
}

# Reachability + per-DC data
$Ping = @{}; $DCFacts = @{}; $DCErrors = @{}
$i = 0
foreach ($dc in $DCs) {
    $i++
    Write-Progress -Activity $act -Status "Collecting from $($dc.HostName)" -PercentComplete (100 * $i / [math]::Max($DCs.Count, 1))
    $Ping[$dc.Name] = Test-Ping $dc.HostName
    try {
        $DCFacts[$dc.Name] = Invoke-OnComputer -ComputerName $dc.HostName -ScriptBlock $DCCollector -ArgumentList $EventDays, $NewAccountDays
    } catch {
        $DCFacts[$dc.Name] = $null
        $DCErrors[$dc.Name] = $_.Exception.Message
    }
}
$DcIPs = @(@($DCs | ForEach-Object { "$($_.IPv4Address)" }) + @($DCFacts.Values | Where-Object { $_ } | ForEach-Object { $_.IPs }) | Where-Object { $_ } | Select-Object -Unique)

# Time offsets relative to the PDC
Write-Progress -Activity $act -Status 'Measuring DC clock offsets'
$RawOffset = @{}
foreach ($dc in $DCs) {
    if ((Get-ShortName $dc.HostName) -eq $env:COMPUTERNAME.ToLower()) { $RawOffset[$dc.Name] = 0.0 }
    else { $RawOffset[$dc.Name] = Get-TimeOffset -Target $dc.HostName }
}
$PdcName   = ($DCs | Where-Object { $_.HostName -ieq $PDC } | Select-Object -First 1).Name
$PdcOffset = $null
if ($PdcName) { $PdcOffset = $RawOffset[$PdcName] }

# Users / computers (one pass each)
Write-Progress -Activity $act -Status 'Reading users and computers'
$HasLegacyLaps = [bool](Get-ADObject -SearchBase $SchemaNC -LDAPFilter '(lDAPDisplayName=ms-Mcs-AdmPwdExpirationTime)')
$HasWinLaps    = [bool](Get-ADObject -SearchBase $SchemaNC -LDAPFilter '(lDAPDisplayName=msLAPS-PasswordExpirationTime)')

$UserProps = 'whenCreated', 'LastLogonDate', 'PasswordLastSet', 'PasswordNeverExpires', 'PasswordNotRequired',
'DoesNotRequirePreAuth', 'AllowReversiblePasswordEncryption', 'UseDESKeyOnly', 'TrustedForDelegation',
'TrustedToAuthForDelegation', 'AccountNotDelegated', 'Description', 'CanonicalName', 'adminCount',
'servicePrincipalName', 'UserPrincipalName', 'DisplayName', 'primaryGroupID', 'Title', 'Department',
'msDS-SupportedEncryptionTypes', 'msDS-AllowedToDelegateTo'
$AllUsers = @(Get-ADUser -Filter * -Properties $UserProps -Server $PDC)

$CompProps = @('OperatingSystem', 'OperatingSystemVersion', 'LastLogonDate', 'whenCreated', 'TrustedForDelegation',
    'TrustedToAuthForDelegation', 'primaryGroupID', 'CanonicalName', 'DNSHostName', 'Description', 'PasswordLastSet',
    'msDS-SupportedEncryptionTypes', 'msDS-AllowedToDelegateTo')
if ($HasLegacyLaps) { $CompProps += 'ms-Mcs-AdmPwdExpirationTime' }
if ($HasWinLaps) { $CompProps += 'msLAPS-PasswordExpirationTime' }
$AllComputers = @(Get-ADComputer -Filter * -Properties $CompProps -Server $PDC)

$UserByDN = @{}; foreach ($u in $AllUsers) { $UserByDN[$u.DistinguishedName] = $u }
$CompByDN = @{}; foreach ($c in $AllComputers) { $CompByDN[$c.DistinguishedName] = $c }
$DCNameSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($dc in $DCs) { [void]$DCNameSet.Add($dc.Name) }

# Privileged groups (by SID so renamed/localised groups still resolve)
Write-Progress -Activity $act -Status 'Expanding privileged groups'
function Expand-PrivGroup {
    param([string]$GroupDN, [string]$Path, $Seen)
    $out = @()
    $g = Get-ADGroup -Identity $GroupDN -Server (Get-ServerForDN $GroupDN) -Properties member
    foreach ($m in $g.member) {
        $o = $null
        try { $o = Get-ADObject -Identity $m -Server (Get-ServerForDN $m) -Properties 'objectClass', 'sAMAccountName', 'objectSid' } catch { }
        if (-not $o) {
            $out += [pscustomobject]@{ DN = $m; Name = $m; Sam = ''; Class = 'unresolved'; Via = $Path; Sid = '' }
            continue
        }
        if ($o.objectClass -eq 'group') {
            if ($Seen.Add($o.DistinguishedName)) {
                $out += Expand-PrivGroup -GroupDN $o.DistinguishedName -Path "$Path > $($o.Name)" -Seen $Seen
            }
        } else {
            $name = $o.Name
            $sid  = "$($o.objectSid)"
            if ($o.objectClass -eq 'foreignSecurityPrincipal') {
                $sid = "$($o.Name)"
                try { $name = ([System.Security.Principal.SecurityIdentifier]$o.Name).Translate([System.Security.Principal.NTAccount]).Value } catch { }
            }
            $out += [pscustomobject]@{ DN = $o.DistinguishedName; Name = $name; Sam = $o.sAMAccountName; Class = $o.objectClass; Via = $Path; Sid = $sid }
        }
    }
    $out
}

$PrivGroupDefs = @(
    @{ Name = 'Enterprise Admins';           Id = "$RootSID-519";  Server = $RootDomain.PDCEmulator; ShouldBeEmpty = $true }
    @{ Name = 'Schema Admins';               Id = "$RootSID-518";  Server = $RootDomain.PDCEmulator; ShouldBeEmpty = $true }
    @{ Name = 'Domain Admins';               Id = "$DomSID-512";   Server = $PDC; ShouldBeEmpty = $false }
    @{ Name = 'Administrators';              Id = 'S-1-5-32-544';  Server = $PDC; ShouldBeEmpty = $false }
    @{ Name = 'Account Operators';           Id = 'S-1-5-32-548';  Server = $PDC; ShouldBeEmpty = $true }
    @{ Name = 'Server Operators';            Id = 'S-1-5-32-549';  Server = $PDC; ShouldBeEmpty = $true }
    @{ Name = 'Print Operators';             Id = 'S-1-5-32-550';  Server = $PDC; ShouldBeEmpty = $true }
    @{ Name = 'Backup Operators';            Id = 'S-1-5-32-551';  Server = $PDC; ShouldBeEmpty = $true }
    @{ Name = 'Group Policy Creator Owners'; Id = "$DomSID-520";   Server = $PDC; ShouldBeEmpty = $false }
    @{ Name = 'Key Admins';                  Id = "$DomSID-526";   Server = $PDC; ShouldBeEmpty = $true }
    @{ Name = 'Enterprise Key Admins';       Id = "$RootSID-527";  Server = $RootDomain.PDCEmulator; ShouldBeEmpty = $true }
    @{ Name = 'DnsAdmins';                   Id = 'DnsAdmins';     Server = $PDC; ShouldBeEmpty = $false }
)

$PrivGroups = @()
foreach ($def in $PrivGroupDefs) {
    try { $g = Get-ADGroup -Identity $def.Id -Server $def.Server } catch { continue }
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    [void]$seen.Add($g.DistinguishedName)
    $members = @()
    try { $members = @(Expand-PrivGroup -GroupDN $g.DistinguishedName -Path $g.Name -Seen $seen) } catch { }

    # When each direct member was added (from replication metadata - independent of log retention)
    $added = @{}; $removed = @()
    try {
        $md = Get-ADReplicationAttributeMetadata -Object $g.DistinguishedName -Server $def.Server -Properties member -ShowAllLinkedValues
        foreach ($v in @($md | Where-Object { $_.AttributeName -eq 'member' })) {
            if ($v.LastOriginatingDeleteTime -and $v.LastOriginatingDeleteTime.Year -gt 1601) {
                $removed += [pscustomobject]@{ Member = $v.AttributeValue; Removed = $v.LastOriginatingDeleteTime }
            } elseif ($v.FirstOriginatingCreateTime -and $v.FirstOriginatingCreateTime.Year -gt 1601) {
                $added[$v.AttributeValue] = $v.FirstOriginatingCreateTime
            }
        }
    } catch { }

    $PrivGroups += [pscustomobject]@{
        Name          = $g.Name
        Key           = $def.Name
        DN            = $g.DistinguishedName
        ShouldBeEmpty = $def.ShouldBeEmpty
        Members       = $members
        Added         = $added
        Removed       = $removed
    }
}

# Privileged accounts: DN -> list of groups
$PrivAccounts = @{}
foreach ($pg in $PrivGroups) {
    foreach ($m in $pg.Members) {
        if (-not $PrivAccounts.ContainsKey($m.DN)) { $PrivAccounts[$m.DN] = New-Object System.Collections.Generic.List[string] }
        if (-not $PrivAccounts[$m.DN].Contains($pg.Name)) { $PrivAccounts[$m.DN].Add($pg.Name) }
    }
}

# Principal classes for the permission checks (section 19 and AD CS)
$script:UnsafeSids = New-Object 'System.Collections.Generic.HashSet[string]'
foreach ($s in 'S-1-1-0', 'S-1-5-7', 'S-1-5-11', 'S-1-5-32-545', 'S-1-0-0', "$DomSID-513", "$DomSID-515") { [void]$script:UnsafeSids.Add($s) }
$script:SafeSids = New-Object 'System.Collections.Generic.HashSet[string]'
foreach ($s in 'S-1-5-18', 'S-1-5-10', 'S-1-3-0', 'S-1-5-9', 'S-1-5-32-544', 'S-1-5-32-548', 'S-1-5-32-549', 'S-1-5-32-550', 'S-1-5-32-551',
    "$DomSID-500", "$DomSID-512", "$DomSID-516", "$DomSID-517", "$DomSID-521", "$DomSID-526",
    "$RootSID-500", "$RootSID-512", "$RootSID-518", "$RootSID-519", "$RootSID-498", "$RootSID-527") { [void]$script:SafeSids.Add($s) }
# Accounts that are already full administrators: rights they hold are not an escalation path
$script:AdminSids = New-Object 'System.Collections.Generic.HashSet[string]'
foreach ($pg in $PrivGroups) {
    if ($pg.Key -ne 'Domain Admins' -and $pg.Key -ne 'Enterprise Admins' -and $pg.Key -ne 'Administrators') { continue }
    foreach ($m in $pg.Members) { if ($m.Sid) { [void]$script:AdminSids.Add($m.Sid) } }
}

# Accurate last logon for privileged accounts: lastLogon is not replicated, so ask every DC and keep the newest
$TrueLastLogon = @{}
foreach ($dc in $DCs) {
    if (-not $DCFacts[$dc.Name]) { continue }
    try {
        foreach ($acct in @(Get-ADUser -LDAPFilter '(adminCount=1)' -Properties lastLogon -Server $dc.HostName)) {
            if ($acct.lastLogon -gt 0) {
                $seenAt = [datetime]::FromFileTime($acct.lastLogon)
                $acctDN = "$($acct.DistinguishedName)"
                if (-not $TrueLastLogon.ContainsKey($acctDN) -or $TrueLastLogon[$acctDN] -lt $seenAt) { $TrueLastLogon[$acctDN] = $seenAt }
            }
        }
    } catch { }
}
function Get-BestLogon {
    # Newest logon known for an account: the replicated value, or a DC's own lastLogon when that is newer
    param($Account)
    $best = $Account.LastLogonDate
    $accountDN = "$($Account.DistinguishedName)"
    if ($TrueLastLogon.ContainsKey($accountDN)) {
        if ($null -eq $best -or $TrueLastLogon[$accountDN] -gt $best) { $best = $TrueLastLogon[$accountDN] }
    }
    return $best
}

# DHCP servers (authorised in AD)
Write-Progress -Activity $act -Status 'Discovering DHCP servers'
$DhcpServers = @()
if (Get-Module -ListAvailable -Name DhcpServer) {
    try { $DhcpServers = @(Get-DhcpServerInDC | ForEach-Object { [pscustomobject]@{ Name = $_.DnsName; IP = "$($_.IPAddress)" } }) } catch { }
}
if ($DhcpServers.Count -eq 0) {
    try {
        $DhcpServers = @(Get-ADObject -SearchBase "CN=NetServices,CN=Services,$ConfigNC" -LDAPFilter '(objectClass=dHCPClass)' |
                Where-Object { $_.Name -ne 'DhcpRoot' } |
                ForEach-Object { [pscustomobject]@{ Name = $_.Name; IP = '' } })
    } catch { }
}
$DhcpData = @{}; $DhcpErr = @{}; $DhcpPing = @{}; $DhcpStale = @{}
foreach ($ds in $DhcpServers) {
    $key = Get-ShortName $ds.Name
    Write-Progress -Activity $act -Status "Collecting DHCP data from $($ds.Name)"
    try { $null = [System.Net.Dns]::GetHostEntry($ds.Name) } catch { $DhcpStale[$key] = $ds.Name; continue }
    $DhcpPing[$key] = Test-Ping $ds.Name
    try { $DhcpData[$key] = Invoke-OnComputer -ComputerName $ds.Name -ScriptBlock $DhcpCollector } catch { $DhcpErr[$key] = $_.Exception.Message }
}
# Pick up failover partners that weren't in the authorised list
foreach ($k in @($DhcpData.Keys)) {
    foreach ($rel in $DhcpData[$k].Failover) {
        $pk = Get-ShortName $rel.Partner
        if (-not $DhcpData.ContainsKey($pk) -and -not $DhcpErr.ContainsKey($pk)) {
            try { $DhcpData[$pk] = Invoke-OnComputer -ComputerName $rel.Partner -ScriptBlock $DhcpCollector } catch { $DhcpErr[$pk] = $_.Exception.Message }
        }
    }
}

# Certificate authorities
$CAs = @()
try {
    $CAs = @(Get-ADObject -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,$ConfigNC" -LDAPFilter '(objectClass=pKIEnrollmentService)' -Properties 'dNSHostName', 'cACertificate', 'displayName', 'certificateTemplates', 'msPKI-Enrollment-Servers')
} catch { }

# Entra Connect / Cloud Sync
$MsolAccounts = @(Get-ADUser -Filter "SamAccountName -like 'MSOL_*'" -Properties 'Description', 'LastLogonDate', 'whenCreated', 'Enabled' -Server $PDC)
$SyncServers = @()
foreach ($m in $MsolAccounts) {
    $srv = ''; $tenant = ''
    if ($m.Description -match 'running on computer (\S+)') { $srv = $Matches[1].TrimEnd('.') }
    if ($m.Description -match 'tenant (\S+)') { $tenant = $Matches[1].TrimEnd('.') }
    $SyncServers += [pscustomobject]@{ Server = $srv; Account = $m.SamAccountName; Tenant = $tenant; Enabled = $m.Enabled; LastLogon = $m.LastLogonDate; Created = $m.whenCreated; Sid = "$($m.SID)" }
}
$CloudSyncGmsa = @()
try { $CloudSyncGmsa = @(Get-ADServiceAccount -Filter "Name -like 'pGMSA_*' -or Name -like 'provAgentgMSA*'" -Server $PDC) } catch { }

# Member servers: enabled Windows Server computer objects that are not DCs
$MemberServers = @($AllComputers | Where-Object { $_.Enabled -and "$($_.OperatingSystem)" -match 'Server' -and -not $DCNameSet.Contains($_.Name) } | Sort-Object Name)
$SrvFacts = @{}; $SrvState = @{}; $SrvPing = @{}
if (-not $SkipMemberServers -and $MemberServers.Count -gt 0) {
    $serverStaleCut = $Now.AddDays(-$StaleDays)
    $serverTargets = @()
    $serverKeyByTarget = @{}
    foreach ($srv in $MemberServers) {
        $key = Get-ShortName $srv.Name
        if (-not $srv.LastLogonDate -or $srv.LastLogonDate -lt $serverStaleCut) { $SrvState[$key] = 'Stale in AD'; continue }
        $fqdn = "$($srv.DNSHostName)"
        if (-not $fqdn) { $fqdn = "$($srv.Name)" }
        Write-Progress -Activity $act -Status "Checking member server $fqdn"
        $SrvPing[$key] = Test-Ping $fqdn
        if (Test-TcpPort -ComputerName $fqdn -Port 5985) {
            $serverTargets += $fqdn
            $serverKeyByTarget[$fqdn.ToLower()] = $key
            $SrvState[$key] = 'Pending'
        } elseif ($SrvPing[$key]) {
            $SrvState[$key] = 'WinRM not reachable'
        } else {
            $SrvState[$key] = 'Offline'
        }
    }
    if ($serverTargets.Count -gt 0) {
        Write-Progress -Activity $act -Status "Collecting from $($serverTargets.Count) member server(s)"
        $serverJob = $null
        try {
            $serverOption = New-PSSessionOption -OpenTimeout 20000 -CancelTimeout 10000
            $serverJob = Invoke-Command -ComputerName $serverTargets -ScriptBlock $ServerCollector -ArgumentList $EventDays -SessionOption $serverOption -AsJob -ThrottleLimit 16
            [void](Wait-Job -Job $serverJob -Timeout $RemoteTimeoutSec)
            foreach ($child in $serverJob.ChildJobs) {
                $key = $serverKeyByTarget["$($child.Location)".ToLower()]
                if (-not $key) { $key = Get-ShortName $child.Location }
                if ($child.State -eq 'Completed') {
                    try {
                        $facts = @(Receive-Job -Job $child -ErrorAction Stop)
                        if ($facts.Count -gt 0) { $SrvFacts[$key] = $facts[0]; $SrvState[$key] = 'Collected' }
                        else { $SrvState[$key] = 'No data returned' }
                    } catch { $SrvState[$key] = "Error: $($_.Exception.Message)" }
                } elseif ($child.State -eq 'Failed') {
                    $reason = 'connection failed'
                    if ($child.JobStateInfo.Reason) { $reason = $child.JobStateInfo.Reason.Message }
                    $SrvState[$key] = "Error: $reason"
                } else {
                    $SrvState[$key] = "No answer within $RemoteTimeoutSec seconds"
                }
            }
        } catch {
            $jobError = $_.Exception.Message
            foreach ($target in $serverTargets) {
                $key = $serverKeyByTarget[$target.ToLower()]
                if ($SrvState[$key] -eq 'Pending') { $SrvState[$key] = "Error: $jobError" }
            }
        } finally {
            if ($serverJob) {
                Stop-Job -Job $serverJob -ErrorAction SilentlyContinue
                Remove-Job -Job $serverJob -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

Write-Progress -Activity $act -Completed

#endregion

#region ============================== Report ==============================

Write-Host ''
Write-Host ('#' * 100) -ForegroundColor White
Write-Host "  ACTIVE DIRECTORY / DOMAIN HEALTH CHECK  -  $DomDNS" -ForegroundColor White
Write-Host "  Run      : $($Now.ToString('yyyy-MM-dd HH:mm'))  on $env:COMPUTERNAME  as $env:USERDOMAIN\$env:USERNAME" -ForegroundColor White
Write-Host "  Windows  : new accounts $NewAccountDays days | stale $StaleDays days | event logs $EventDays days" -ForegroundColor White
Write-Host "  Mode     : READ-ONLY - no configuration changes are made   (script version $ScriptVersion)" -ForegroundColor White
Write-Host ('#' * 100) -ForegroundColor White
Write-Host '  Legend   : ' -NoNewline
Write-Host '[FAIL]' -ForegroundColor White -BackgroundColor DarkRed -NoNewline
Write-Host ' fix now   ' -NoNewline
Write-Host '[WARN]' -ForegroundColor Black -BackgroundColor Yellow -NoNewline
Write-Host ' review   ' -NoNewline
Write-Host '[PASS]' -ForegroundColor DarkGreen -NoNewline
Write-Host ' healthy   [INFO] context   table rows: !! = fail, ! = warn'
if ($IssuesOnly) { Write-Host '  View     : issues only (-IssuesOnly). PASS, INFO and tables are hidden.' -ForegroundColor White }
if ((Get-AgeDays $Baseline.Reviewed) -gt 120) {
    Write-Host "  Note     : the dated baselines in this script were last reviewed $(Format-Date $Baseline.Reviewed). Check for newer Microsoft guidance." -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------------------------
Write-Section '1. ENVIRONMENT OVERVIEW'
try {
    $schemaVer = (Get-ADObject $SchemaNC -Properties objectVersion).objectVersion
    $schemaMap = @{ 30 = '2003'; 31 = '2003 R2'; 44 = '2008'; 47 = '2008 R2'; 56 = '2012'; 69 = '2012 R2'; 87 = '2016'; 88 = '2019/2022'; 91 = '2025' }
    $schemaName = $schemaMap[[int]$schemaVer]; if (-not $schemaName) { $schemaName = 'unknown' }

    Write-Info "Forest          : $($Forest.Name)   (forest functional level: $($Forest.ForestMode))"
    Write-Info "Domain          : $DomDNS  [$($Domain.NetBIOSName)]   (domain functional level: $($Domain.DomainMode))"
    Write-Info "Schema version  : $schemaVer  (Windows Server $schemaName)"
    Write-Info "Domains/forest  : $(@($Forest.Domains).Count)   Sites: $(@($Forest.Sites).Count)   DCs in domain: $($DCs.Count)"

    if ("$($Domain.DomainMode)" -match '2000|2003|2008|2012') {
        Write-Status WARN "Domain functional level is $($Domain.DomainMode) - Windows2016Domain is the practical floor for current features"
    } else { Write-Status PASS "Domain functional level $($Domain.DomainMode)" }

    $rb = Get-ADOptionalFeature -Filter "Name -eq 'Recycle Bin Feature'"
    if ($rb -and @($rb.EnabledScopes).Count -gt 0) { Write-Status PASS 'AD Recycle Bin is enabled' }
    else { Write-Status WARN 'AD Recycle Bin is NOT enabled (deleted objects cannot be restored with attributes/group memberships)' }

    $tombstoneDays = (Get-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,$ConfigNC" -Properties tombstoneLifetime).tombstoneLifetime
    if (-not $tombstoneDays) { $tombstoneDays = 60; Write-Status INFO 'Tombstone lifetime not set (defaults to 60 days)' }
    else { Write-Status INFO "Tombstone lifetime: $tombstoneDays days" }
    $script:TSL = [int]$tombstoneDays

    if ($DCs.Count -eq 1) { Write-Status WARN 'Only ONE domain controller - no AD/DNS redundancy; a DC failure is a full outage' }
    else { Write-Status PASS "$($DCs.Count) domain controllers" }

    Write-Sub 'FSMO role holders'
    $fsmo = @(
        [pscustomobject]@{ Role = 'Schema Master';         Holder = $Forest.SchemaMaster }
        [pscustomobject]@{ Role = 'Domain Naming Master';  Holder = $Forest.DomainNamingMaster }
        [pscustomobject]@{ Role = 'PDC Emulator';          Holder = $Domain.PDCEmulator }
        [pscustomobject]@{ Role = 'RID Master';            Holder = $Domain.RIDMaster }
        [pscustomobject]@{ Role = 'Infrastructure Master'; Holder = $Domain.InfrastructureMaster }
    )
    foreach ($f in $fsmo) {
        $f | Add-Member -NotePropertyName Online -NotePropertyValue (Test-Ping $f.Holder)
    }
    Show-Table $fsmo -Flag { param($row) if (-not $row.Online) { 'FAIL' } }
    foreach ($f in $fsmo) {
        if (-not $f.Online) { Write-Status FAIL "FSMO holder for $($f.Role) ($($f.Holder)) does not respond to ping" }
        elseif (-not $ForestDCNames.Contains((Get-ShortName $f.Holder))) {
            if ($UnverifiedNote) { Write-Status WARN "$($f.Role) holder $($f.Holder) was not found in the DC list$UnverifiedNote" }
            else { Write-Status FAIL "$($f.Role) holder $($f.Holder) is not a current DC (seize/transfer needed)" }
        }
    }

    Write-Sub 'Domain controllers'
    Show-Table ($DCs | ForEach-Object {
            [pscustomobject]@{
                Name    = $_.Name
                Site    = $_.Site
                IPv4    = $_.IPv4Address
                OS      = $_.OperatingSystem
                GC      = $_.IsGlobalCatalog
                RODC    = $_.IsReadOnly
                Ping    = $Ping[$_.Name]
                Virtual = $(if ($DCFacts[$_.Name]) { $DCFacts[$_.Name].IsVirtual } else { '?' })
                Roles   = (@($_.OperationMasterRoles) | ForEach-Object { "$_" -replace 'Master|Emulator', '' }) -join ','
            }
        }) -Flag { param($row) if (-not $row.Ping) { 'FAIL' } }

    Write-Sub 'Sites and subnets'
    $sites   = @(Get-ADReplicationSite -Filter * -Server $PDC)
    $subnets = @(Get-ADReplicationSubnet -Filter * -Properties Site -Server $PDC)
    Show-Table ($sites | ForEach-Object {
            $sDN = $_.DistinguishedName; $sName = $_.Name
            [pscustomobject]@{
                Site    = $sName
                Subnets = (@($subnets | Where-Object { $_.Site -eq $sDN } | ForEach-Object { $_.Name }) -join ', ')
                DCs     = (@($DCs | Where-Object { $_.Site -eq $sName } | ForEach-Object { $_.Name }) -join ', ')
            }
        })
    if ($subnets.Count -eq 0) {
        if ($sites.Count -gt 1) { Write-Status WARN 'No AD subnets defined but multiple sites exist - clients cannot find their local DC' }
        else { Write-Status INFO 'No AD subnets defined (single site - low impact, but define subnets for clean DC locator behaviour)' }
    }
    foreach ($s in $sites) {
        if ($sites.Count -gt 1 -and -not ($subnets | Where-Object { $_.Site -eq $s.DistinguishedName })) {
            Write-Status WARN "Site '$($s.Name)' has no subnets assigned"
        }
    }

    Write-Sub 'Infrastructure discovered from AD'
    $dnsDcNames = @($DCs | Where-Object { $DCFacts[$_.Name] -and ($DCFacts[$_.Name].Services | Where-Object { $_.Name -eq 'DNS' -and $_.Status -eq 'Running' }) } | ForEach-Object { $_.Name })
    Write-Info ("DNS servers (DCs)   : " + $(if ($dnsDcNames) { $dnsDcNames -join ', ' } else { 'none detected' }))
    Write-Info ("DHCP (authorised)   : " + $(if ($DhcpServers) { ($DhcpServers | ForEach-Object { $_.Name }) -join ', ' } else { 'none - likely on firewall/router' }))
    Write-Info ("Certificate auth.   : " + $(if ($CAs) { ($CAs | ForEach-Object { "$($_.Name) on $($_.dNSHostName)" }) -join '; ' } else { 'none' }))
    Write-Info ("Entra Connect       : " + $(if ($SyncServers) { ($SyncServers | ForEach-Object { "$($_.Server) ($($_.Tenant))" }) -join '; ' } else { 'not detected' }))
    if ($CloudSyncGmsa) { Write-Info ("Entra Cloud Sync    : gMSA present ($(($CloudSyncGmsa | ForEach-Object { $_.Name }) -join ', '))") }
    Write-Info "Member servers      : $($MemberServers.Count) enabled Windows Server computer object(s) besides the DCs (section 20)"
    Write-Info "Users / computers   : $($AllUsers.Count) users ($(@($AllUsers | Where-Object { $_.Enabled }).Count) enabled), $($AllComputers.Count) computers ($(@($AllComputers | Where-Object { $_.Enabled }).Count) enabled)"
} catch { Write-Status FAIL "Section error: $($_.Exception.Message)" }

# ---------------------------------------------------------------------------------------------
Write-Section '2. DOMAIN CONTROLLER HEALTH'
foreach ($dc in $DCs) {
    try {
        $tag = $dc.Name + ':'
        Write-Sub "$($dc.HostName)  ($($dc.OperatingSystem))"
        if ($Ping[$dc.Name]) { Write-Status PASS "$tag responds to ping" } else { Write-Status FAIL "$tag does not respond to ping" }
        $f = $DCFacts[$dc.Name]
        if (-not $f) { Write-Status FAIL "$tag could not collect data over WinRM - $($DCErrors[$dc.Name])"; continue }

        $up = Get-AgeDays $f.LastBoot
        if ($null -eq $up) { Write-Status INFO "$tag uptime unknown" }
        elseif ($up -gt $Baseline.MaxDcUptimeDays) { Write-Status WARN "$tag uptime $up days (last boot $(Format-Date $f.LastBoot)) - likely behind on patches" }
        else { Write-Status PASS "$tag uptime $up days" }

        $pa = Get-AgeDays $f.LastPatch
        if ($null -eq $pa) { Write-Status WARN "$tag could not determine the last patch date" }
        elseif ($pa -gt $Baseline.MaxPatchAgeDays) { Write-Status WARN "$tag last update installed $pa days ago ($($f.LastPatchKB) on $(Format-Date $f.LastPatch))" }
        else { Write-Status PASS "$tag last update installed $pa days ago ($($f.LastPatchKB))" }

        if ($f.PendingReboot) { Write-Status WARN "$tag reboot pending (Windows Update / CBS)" }

        if ($null -ne $f.RamUsedPct) {
            $ramMsg = "$tag memory $($f.RamUsedPct)% used ($($f.RamFreeGB) GB free of $($f.RamTotalGB) GB)"
            if ($f.RamUsedPct -ge 95) { Write-Status FAIL $ramMsg } elseif ($f.RamUsedPct -ge 85) { Write-Status WARN $ramMsg } else { Write-Status PASS $ramMsg }
        }
        if ($null -ne $f.CpuLoadPct) {
            $cpuMsg = "$tag CPU load $($f.CpuLoadPct)% (one sample taken during collection)"
            if ($f.CpuLoadPct -ge 90) { Write-Status WARN $cpuMsg } else { Write-Status PASS $cpuMsg }
        }

        $svcOk = @(); $svcBad = @()
        foreach ($s in $f.Services) {
            if ($s.Status -eq 'Running') { $svcOk += $s.Name; continue }
            if ($s.Status -eq 'NotInstalled') {
                if ($s.Name -eq 'DNS') { Write-Status INFO "$tag DNS Server role is not installed on this DC" }
                elseif ($s.Name -ne 'IsmServ') { $svcBad += "$($s.Name) (not installed)" }
                continue
            }
            $svcBad += "$($s.Name) ($($s.Status)/$($s.StartType))"
        }
        if ($svcOk) { Write-Status PASS "$tag services running - $($svcOk -join ', ')" }
        foreach ($b in $svcBad) { Write-Status FAIL "$tag service problem - $b" }

        foreach ($d in $f.Disks) {
            $holds = ''
            if ($d.Holds) { $holds = " [$($d.Holds)]" }
            $msg = "$tag drive $($d.Drive) $($d.FreeGB) GB free of $($d.SizeGB) GB ($($d.FreePct)%)$holds"
            if ($d.FreePct -lt 10) { Write-Status FAIL $msg } elseif ($d.FreePct -lt 20) { Write-Status WARN $msg } else { Write-Status PASS $msg }
        }
        if ($f.NtdsDbGB) { Write-Status INFO "$tag NTDS.dit size $($f.NtdsDbGB) GB  ($($f.NtdsDb))" }

        foreach ($sh in 'SYSVOL', 'NETLOGON') {
            if ($f.Shares -contains $sh) { Write-Status PASS "$tag $sh share present" } else { Write-Status FAIL "$tag $sh share MISSING (DC not advertising correctly)" }
        }

        $valid   = @($f.Certs | Where-Object { $_.NotAfter -gt $Now })
        $expired = @($f.Certs | Where-Object { $_.NotAfter -le $Now })
        if ($valid.Count -eq 0) {
            if ($CAs) { Write-Status WARN "$tag no valid Server Auth / KDC certificate (LDAPS and certificate-based auth unavailable) even though an enterprise CA exists" }
            else { Write-Status INFO "$tag no server authentication certificate (no enterprise CA - LDAPS not available)" }
        } else {
            $next = $valid | Sort-Object NotAfter -Descending | Select-Object -First 1
            $days = [int]($next.NotAfter - $Now).TotalDays
            if ($days -lt 30) { Write-Status WARN "$tag newest DC certificate expires in $days days ($(Format-Date $next.NotAfter)) - check autoenrollment" }
            else { Write-Status PASS "$tag DC certificate valid until $(Format-Date $next.NotAfter)" }
        }
        if ($expired.Count) { Write-Status INFO "$tag $($expired.Count) expired certificate(s) still in the computer store (cleanup)" }
    } catch { Write-Status FAIL "Section error on $($dc.Name): $($_.Exception.Message)" }
}

# ---------------------------------------------------------------------------------------------
Write-Section '3. DCDIAG (dcdiag /e /q - errors only)'
try {
    $dd = @(Invoke-Native -Exe 'dcdiag.exe' -Arguments @('/e', '/q') -TimeoutSec 600 | Where-Object { $_.Trim() })
    if ($dd.Count -eq 0) {
        Write-Status PASS 'dcdiag reported no errors on any DC'
    } else {
        foreach ($l in (Compress-DcdiagOutput $dd)) { Write-Detail $l }
        $noisy = 'SystemLog', 'DFSREvent', 'KccEvent', 'FrsEvent'
        $dcdiagFailures = 0
        foreach ($l in $dd) {
            if ($l -match '\.{3,}\s*(\S+)\s+failed test\s+(\S+)') {
                $srv = $Matches[1]; $test = $Matches[2]
                $dcdiagFailures++
                if ($test -in $noisy) { Write-Status WARN "dcdiag: $srv failed $test (event-based test - see section 21)" }
                else { Write-Status FAIL "dcdiag: $srv failed test $test" }
            }
        }
        if ($dcdiagFailures -eq 0) { Write-Status WARN 'dcdiag printed output but no failed test could be identified - run dcdiag /e /q by hand to read it' }
    }
} catch { Write-Status FAIL "Section error: $($_.Exception.Message)" }

# ---------------------------------------------------------------------------------------------
Write-Section '4. AD REPLICATION'
try {
    if ($DCs.Count -lt 2) {
        Write-Status INFO 'Single DC - no replication partners to check'
    } else {
        $csvLines = @(Invoke-Native -Exe 'repadmin.exe' -Arguments @('/showrepl', '*', '/csv') -TimeoutSec 180 | Where-Object { $_.Trim() })
        $rows = @($csvLines | ConvertFrom-Csv)
        $infoRows = @($rows | Where-Object { $_.'showrepl_COLUMNS' -eq 'showrepl_INFO' })
        $errRows  = @($rows | Where-Object { $_.'showrepl_COLUMNS' -eq 'showrepl_ERROR' })

        $replTable = foreach ($r in $infoRows) {
            $fails = 0; [void][int]::TryParse("$($r.'Number of Failures')", [ref]$fails)
            $ls = ConvertTo-DateSafe $r.'Last Success Time'
            $ageH = $null; if ($ls) { $ageH = [math]::Round(($Now - $ls).TotalHours, 1) }
            $nc = ($r.'Naming Context' -split ',')[0]
            $status = 'OK'
            if ($fails -gt 0) { $status = 'FAIL' } elseif ($null -eq $ageH -or $ageH -gt 24) { $status = 'STALE' }
            [pscustomobject]@{
                Destination   = $r.'Destination DSA'
                Source        = $r.'Source DSA'
                Partition     = $nc
                Failures      = $fails
                LastSuccess   = $(if ($ls) { $ls.ToString('yyyy-MM-dd HH:mm') } else { 'never' })
                AgeHours      = $ageH
                LastError     = $(if ($fails -gt 0) { $r.'Last Failure Status' } else { '' })
                Status        = $status
            }
        }
        Show-Table $replTable -Flag { param($row) if ($row.Status -eq 'FAIL') { 'FAIL' } elseif ($row.Status -ne 'OK') { 'WARN' } }
        $bad = @($replTable | Where-Object { $_.Status -ne 'OK' })
        if ($bad.Count -eq 0 -and $errRows.Count -eq 0) { Write-Status PASS "All $(@($replTable).Count) replication links healthy (no failures, all succeeded within 24h)" }
        foreach ($b in $bad) {
            if ($b.Status -eq 'FAIL') { Write-Status FAIL "$($b.Source) -> $($b.Destination) [$($b.Partition)] $($b.Failures) failure(s), last error $($b.LastError), last success $($b.LastSuccess)" }
            else { Write-Status WARN "$($b.Source) -> $($b.Destination) [$($b.Partition)] last success $($b.LastSuccess)" }
            if ($b.AgeHours -and $b.AgeHours -gt (24 * $script:TSL)) { Write-Status FAIL "$($b.Destination) has not replicated $($b.Partition) within the tombstone lifetime - lingering objects risk" }
        }
        foreach ($e in $errRows) { Write-Status FAIL "repadmin error: $(($e.PSObject.Properties.Value | Where-Object { $_ }) -join ' | ')" }

        $rf = @(Get-ADReplicationFailure -Target $DomDNS -Scope Domain -ErrorAction SilentlyContinue | Where-Object { $_.FailureCount -gt 0 })
        if ($rf) {
            Write-Sub 'Get-ADReplicationFailure'
            Show-Table ($rf | ForEach-Object { [pscustomobject]@{ Server = $_.Server; Partner = (($_.Partner -split ',')[1] -replace 'CN=', ''); Count = $_.FailureCount; First = $_.FirstFailureTime; LastError = $_.LastError } })
        }

        Write-Sub 'repadmin /replsummary'
        foreach ($l in (Invoke-Native -Exe 'repadmin.exe' -Arguments @('/replsummary') -TimeoutSec 180)) { if ($l.Trim()) { Write-Detail $l } }
    }

    Write-Sub 'DC metadata consistency'
    $serverObjs = @(Get-ADObject -SearchBase "CN=Sites,$ConfigNC" -LDAPFilter '(objectClass=server)' -Server $PDC)
    $ntdsObjs   = @(Get-ADObject -SearchBase "CN=Sites,$ConfigNC" -LDAPFilter '(objectClass=nTDSDSA)' -Server $PDC)
    $metaIssues = 0
    foreach ($so in $serverObjs) {
        $hasNtds = $ntdsObjs | Where-Object { $_.DistinguishedName -like "*,$($so.DistinguishedName)" }
        if (-not $hasNtds) { Write-Status WARN "Server object '$($so.Name)' in Sites has no NTDS Settings (leftover from a removed DC - can be deleted)"; $metaIssues++ }
        elseif (-not $ForestDCNames.Contains($so.Name)) {
            if ($UnverifiedNote) { Write-Status WARN "NTDS Settings exist for '$($so.Name)' but it was not found in the DC list$UnverifiedNote. Do not run metadata cleanup until that is resolved" }
            else { Write-Status FAIL "NTDS Settings exist for '$($so.Name)' but it is not a current DC - metadata cleanup needed" }
            $metaIssues++
        }
    }
    $dcComputerObjs = @($AllComputers | Where-Object { $_.primaryGroupID -eq 516 -or $_.primaryGroupID -eq 521 })
    foreach ($c in $dcComputerObjs) {
        if (-not $DCNameSet.Contains($c.Name)) { Write-Status WARN "Computer '$($c.Name)' has a DC primary group but is not an active DC (stale DC object?)"; $metaIssues++ }
    }
    if ($metaIssues -eq 0) { Write-Status PASS 'No stale DC metadata found' }
} catch { Write-Status FAIL "Section error: $($_.Exception.Message)" }

# ---------------------------------------------------------------------------------------------
Write-Section '5. SYSVOL / DFSR'
try {
    $mig = (Invoke-Native -Exe 'dfsrmig.exe' -Arguments @('/getglobalstate')) -join ' '
    if ($mig -match 'Eliminated') { Write-Status PASS 'SYSVOL replicates with DFSR (migration state: Eliminated)' }
    elseif ($mig -match "'(Start|Prepared|Redirected)'") { Write-Status FAIL "SYSVOL FRS->DFSR migration is incomplete (state: $($Matches[1]))" }
    elseif ($mig -match 'not .*initiali') { Write-Status FAIL 'SYSVOL still replicates with FRS (deprecated; blocks adding Server 2019+ DCs)' }
    else { Write-Status WARN "Could not determine DFSR migration state: $(Limit-Text $mig 120)" }

    $stateMap = @{ 0 = 'Uninitialized'; 1 = 'Initialized'; 2 = 'Initial Sync'; 3 = 'Auto Recovery'; 4 = 'Normal'; 5 = 'In Error' }
    foreach ($dc in $DCs) {
        $f = $DCFacts[$dc.Name]
        if (-not $f) { Write-Status WARN "$($dc.Name): no data collected"; continue }
        if ($null -eq $f.SysvolDfsrState) { Write-Status WARN "$($dc.Name): could not read DFSR SYSVOL state" }
        elseif ($f.SysvolDfsrState -eq 4) { Write-Status PASS "$($dc.Name): SYSVOL DFSR state Normal" }
        else { Write-Status FAIL "$($dc.Name): SYSVOL DFSR state $($stateMap[[int]$f.SysvolDfsrState])" }

        if ($f.Last2213 -and (-not $f.Last2214 -or $f.Last2214 -lt $f.Last2213)) {
            Write-Status FAIL "$($dc.Name): DFSR event 2213 (replication paused after dirty shutdown) on $(Format-Date $f.Last2213) with no later resume (2214)"
        }
        if ($f.Last4012 -and (Get-AgeDays $f.Last4012) -le 60) {
            Write-Status FAIL "$($dc.Name): DFSR event 4012 on $(Format-Date $f.Last4012) - SYSVOL replication stopped (content freshness)"
        }
    }

    Write-Sub 'GPO folder count in SYSVOL per DC (should match)'
    $guidRx = '^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$'
    $gpoFolderCounts = foreach ($dc in $DCs) {
        $p = "\\$($dc.HostName)\SYSVOL\$DomDNS\Policies"
        $n = $null
        try { $n = @(Get-ChildItem -LiteralPath $p -Directory | Where-Object { $_.Name -match $guidRx }).Count } catch { }
        [pscustomobject]@{ DC = $dc.Name; PolicyFolders = $(if ($null -eq $n) { 'unreachable' } else { $n }) }
    }
    Show-Table $gpoFolderCounts
    $distinct = @($gpoFolderCounts | Where-Object { $_.PolicyFolders -ne 'unreachable' } | ForEach-Object { $_.PolicyFolders } | Select-Object -Unique)
    if ($distinct.Count -gt 1) { Write-Status WARN 'SYSVOL policy folder counts differ between DCs - SYSVOL is not fully in sync' }
    elseif ($distinct.Count -eq 1) { Write-Status PASS 'SYSVOL policy folder counts match on all reachable DCs' }
    foreach ($c in $gpoFolderCounts) { if ($c.PolicyFolders -eq 'unreachable') { Write-Status FAIL "Cannot read \\$($c.DC)\SYSVOL" } }
} catch { Write-Status FAIL "Section error: $($_.Exception.Message)" }

# ---------------------------------------------------------------------------------------------
Write-Section '6. TIME / NTP'
try {
    $timeRows = foreach ($dc in $DCs) {
        $f = $DCFacts[$dc.Name]
        $rel = $null
        if ($null -ne $RawOffset[$dc.Name] -and $null -ne $PdcOffset) { $rel = [math]::Round($RawOffset[$dc.Name] - $PdcOffset, 3) }
        [pscustomobject]@{
            DC          = $dc.Name
            PDC         = ($dc.HostName -ieq $PDC)
            Type        = $(if ($f) { $f.TimeType } else { '?' })
            Source      = $(if ($f) { Limit-Text $f.TimeSource 40 } else { '?' })
            NtpServer   = $(if ($f) { Limit-Text $f.NtpServer 40 } else { '?' })
            Stratum     = $(if ($f) { $f.Stratum } else { '' })
            LastSync    = $(if ($f -and $f.LastTimeSync) { $f.LastTimeSync.ToString('yyyy-MM-dd HH:mm') } else { '' })
            OffsetVsPDC = $rel
            Virtual     = $(if ($f) { $f.IsVirtual } else { '' })
        }
    }
    Show-Table $timeRows -Flag {
        param($row)
        if ("$($row.Source)" -match 'Local CMOS|Free-running|VM IC') { 'FAIL' }
        elseif ($null -ne $row.OffsetVsPDC -and [math]::Abs([double]$row.OffsetVsPDC) -gt 5) { 'FAIL' }
        elseif ($null -ne $row.OffsetVsPDC -and [math]::Abs([double]$row.OffsetVsPDC) -gt 1) { 'WARN' }
    }

    foreach ($dc in $DCs) {
        $f = $DCFacts[$dc.Name]
        if (-not $f) { Write-Status WARN "$($dc.Name): no time data collected"; continue }
        # Only the forest-root PDC should sync from an external source; a child domain's PDC follows the hierarchy
        $isThisPdc = ($dc.HostName -ieq $PDC)
        $isPdc = $isThisPdc -and ($DomDNS -ieq $Forest.RootDomain)
        $src = "$($f.TimeSource)"

        if ($src -match 'Local CMOS Clock|Free-running') { Write-Status FAIL "$($dc.Name): time source is '$src' - not syncing from anything" }
        elseif ($src -match 'VM IC') { Write-Status FAIL "$($dc.Name): time source is the hypervisor (VM IC Time Synchronization Provider) - disable host time sync for this DC" }
        elseif ($src -match 'error|0x800[0-9A-Fa-f]{5}') { Write-Status FAIL "$($dc.Name): w32tm error: $(Limit-Text $src 80)" }

        if ($isPdc) {
            if ($f.TimeType -ne 'NTP' -and $f.TimeType -ne 'AllSync') { Write-Status WARN "$($dc.Name) (PDC): W32Time Type is '$($f.TimeType)' - the PDC should be Type=NTP pointing at reliable external/internal NTP peers" }
            elseif ($src -notmatch 'Local CMOS|Free-running|VM IC|error') { Write-Status PASS "$($dc.Name) (PDC): syncs from $src (NtpServer: $($f.NtpServer))" }
        } else {
            if ($f.TimeType -ne 'NT5DS') { Write-Status WARN "$($dc.Name): W32Time Type is '$($f.TimeType)' - non-PDC DCs should use NT5DS (domain hierarchy)" }
            elseif ($src -notmatch 'Local CMOS|Free-running|VM IC|error') { Write-Status PASS "$($dc.Name): follows domain hierarchy (source $src)" }
        }

        if ($f.LeapIndicator -eq 3) { Write-Status FAIL "$($dc.Name): w32tm reports Leap Indicator 3 (not synchronized)" }
        $syncAge = $null
        if ($f.LastTimeSync) { $syncAge = ($Now - $f.LastTimeSync).TotalHours }
        if ($null -ne $syncAge -and $syncAge -gt 24) { Write-Status WARN "$($dc.Name): last successful time sync $([math]::Round($syncAge,0)) hours ago" }

        if ($f.IsVirtual -and $f.VMICEnabled -eq 1 -and $src -notmatch 'VM IC') {
            Write-Status INFO "$($dc.Name): Hyper-V time provider enabled in registry (not currently the source)"
        }

        if (-not $isThisPdc) {
            $rel = ($timeRows | Where-Object { $_.DC -eq $dc.Name }).OffsetVsPDC
            if ($null -eq $rel) { Write-Status WARN "$($dc.Name): could not measure clock offset vs PDC" }
            elseif ([math]::Abs($rel) -gt 5) { Write-Status FAIL "$($dc.Name): clock is $rel s off the PDC" }
            elseif ([math]::Abs($rel) -gt 1) { Write-Status WARN "$($dc.Name): clock is $rel s off the PDC" }
            else { Write-Status PASS "$($dc.Name): clock within $([math]::Abs($rel)) s of PDC" }
        }
    }
} catch { Write-Status FAIL "Section error: $($_.Exception.Message)" }

# ---------------------------------------------------------------------------------------------
Write-Section '7. DNS'
try {
    Write-Sub 'DC network adapter DNS client settings'
    foreach ($dc in $DCs) {
        $f = $DCFacts[$dc.Name]; if (-not $f) { continue }
        $own = @($f.IPs) + '127.0.0.1'
        foreach ($nic in $f.DnsClient) {
            $servers  = @($nic.Servers)
            $list     = $servers -join ', '
            $external = @($servers | Where-Object { $_ -notin $DcIPs -and $_ -ne '127.0.0.1' -and $_ -ne '::1' })
            $partners = @($servers | Where-Object { $_ -notin $own -and $_ -in $DcIPs })
            if ($external) { Write-Status FAIL "$($dc.Name) [$($nic.Interface)]: uses non-DC DNS server(s) $($external -join ', ') (DCs must only use AD DNS) - list: $list" }
            elseif ($DCs.Count -gt 1 -and $partners.Count -eq 0) { Write-Status WARN "$($dc.Name) [$($nic.Interface)]: points only to itself ($list) - add a partner DC (partner first, own IP/loopback second)" }
            else { Write-Status PASS "$($dc.Name) [$($nic.Interface)]: $list" }
        }
    }

    $dnsDCs = @($DCs | Where-Object { $DCFacts[$_.Name] -and ($DCFacts[$_.Name].Services | Where-Object { $_.Name -eq 'DNS' -and $_.Status -eq 'Running' }) })
    if ($dnsDCs.Count -eq 0) { Write-Status WARN 'No DCs with a running DNS Server service detected - DNS checks skipped'; throw 'skip' }
    $hasDnsModule = [bool](Get-Module -ListAvailable -Name DnsServer)

    Write-Sub 'DC locator records (SRV / CNAME / A) on each DNS server'
    $forestRoot = $Forest.RootDomain
    $knownHosts = @($DCs | ForEach-Object { $_.HostName }) + @($Forest.GlobalCatalogs)
    $checks = @(
        [pscustomobject]@{ Record = "_ldap._tcp.dc._msdcs.$DomDNS";     Expect = @($WritableDCs | ForEach-Object { $_.HostName }) }
        [pscustomobject]@{ Record = "_kerberos._tcp.dc._msdcs.$DomDNS"; Expect = @($WritableDCs | ForEach-Object { $_.HostName }) }
        [pscustomobject]@{ Record = "_ldap._tcp.pdc._msdcs.$DomDNS";    Expect = @($PDC) }
        [pscustomobject]@{ Record = "_ldap._tcp.gc._msdcs.$forestRoot"; Expect = @($WritableDCs | Where-Object { $_.IsGlobalCatalog } | ForEach-Object { $_.HostName }) }
    )
    foreach ($ns in $dnsDCs) {
        $issues = @()
        foreach ($chk in $checks) {
            try {
                $targets = @(Resolve-DnsName -Name $chk.Record -Type SRV -Server $ns.HostName -DnsOnly | Where-Object { $_.NameTarget } | ForEach-Object { $_.NameTarget.TrimEnd('.') })
            } catch { $targets = @() }
            foreach ($e in $chk.Expect) { if ($e -notin $targets) { $issues += "FAIL|$($chk.Record) missing $e" } }
            foreach ($t in $targets) { if ($t -notin $chk.Expect -and $t -notin $knownHosts) { $issues += "WARN|$($chk.Record) has stale target $t" } }
        }
        foreach ($dc in $DCs) {
            try {
                $guid = (Get-ADObject -Identity $dc.NTDSSettingsObjectDN -Properties objectGUID -Server $PDC).objectGUID
                $cn = @(Resolve-DnsName -Name "$guid._msdcs.$forestRoot" -Type CNAME -Server $ns.HostName -DnsOnly | Where-Object { $_.NameHost })
                if (-not $cn -or $cn[0].NameHost.TrimEnd('.') -ne $dc.HostName) { $issues += "FAIL|$($dc.Name) DSA GUID CNAME ($guid._msdcs) missing or wrong" }
            } catch { $issues += "FAIL|$($dc.Name) DSA GUID CNAME lookup failed" }
            try {
                $a = @(Resolve-DnsName -Name $dc.HostName -Type A -Server $ns.HostName -DnsOnly | Where-Object { $_.IPAddress } | ForEach-Object { $_.IPAddress })
                if ("$($dc.IPv4Address)" -notin $a) { $issues += "FAIL|$($dc.HostName) A record missing $($dc.IPv4Address)" }
                $extra = @($a | Where-Object { $_ -ne "$($dc.IPv4Address)" })
                if ($extra) { $issues += "WARN|$($dc.HostName) has extra A record(s) $($extra -join ', ') (multi-homed DC or stale record)" }
            } catch { $issues += "FAIL|$($dc.HostName) A record lookup failed" }
        }
        if ($issues.Count -eq 0) { Write-Status PASS "$($ns.Name): all DC locator SRV, GUID CNAME and A records present and correct" }
        foreach ($is in $issues) { $p = $is -split '\|', 2; Write-Status $p[0] "$($ns.Name): $($p[1])" }
    }

    if (-not $hasDnsModule) { Write-Status WARN 'DnsServer PowerShell module not available - zone/forwarder/scavenging checks skipped'; throw 'skip' }

    Write-Sub 'Forwarders'
    $fwdSets = @{}
    foreach ($ns in $dnsDCs) {
        $fwd = Get-DnsServerForwarder -ComputerName $ns.HostName
        $ips = @(@($fwd.IPAddress) | Where-Object { $_ } | ForEach-Object { "$_" })
        $fwdSets[$ns.Name] = ($ips | Sort-Object) -join ','
        if ($ips.Count -eq 0) { Write-Status INFO "$($ns.Name): no forwarders (root hints only: $($fwd.UseRootHint))"; continue }
        foreach ($ip in $ips) {
            try {
                $null = Resolve-DnsName -Name 'www.microsoft.com' -Server $ip -DnsOnly -QuickTimeout -ErrorAction Stop
                Write-Status PASS "$($ns.Name): forwarder $ip answers"
            } catch { Write-Status FAIL "$($ns.Name): forwarder $ip does NOT answer queries" }
        }
    }
    if (@($fwdSets.Values | Select-Object -Unique).Count -gt 1) { Write-Status WARN "Forwarders differ between DNS servers: $(($fwdSets.GetEnumerator() | ForEach-Object { "$($_.Key)=[$($_.Value)]" }) -join '  ')" }

    Write-Sub 'Zones'
    $zsrv = ($dnsDCs | Where-Object { (Get-ShortName $_.HostName) -eq $env:COMPUTERNAME.ToLower() } | Select-Object -First 1)
    if (-not $zsrv) { $zsrv = $dnsDCs[0] }
    $zones = @(Get-DnsServerZone -ComputerName $zsrv.HostName | Where-Object { -not $_.IsAutoCreated -and $_.ZoneName -ne 'TrustAnchors' })
    $zoneRows = foreach ($z in $zones) {
        $aging = ''
        if ($z.ZoneType -eq 'Primary') { try { $aging = (Get-DnsServerZoneAging -Name $z.ZoneName -ComputerName $zsrv.HostName).AgingEnabled } catch { } }
        [pscustomobject]@{
            Zone          = $z.ZoneName
            Type          = $z.ZoneType
            ADIntegrated  = $z.IsDsIntegrated
            Replication   = $z.ReplicationScope
            DynamicUpdate = $z.DynamicUpdate
            Reverse       = $z.IsReverseLookupZone
            Aging         = $aging
            Masters       = (@($z.MasterServers) | ForEach-Object { "$_" }) -join ','
        }
    }
    Show-Table $zoneRows -Flag {
        param($row)
        if ("$($row.Type)" -eq 'Primary' -and "$($row.DynamicUpdate)" -eq 'NonsecureAndSecure' -and -not $row.Reverse) { 'WARN' }
        elseif ("$($row.Type)" -eq 'Primary' -and -not $row.ADIntegrated) { 'WARN' }
    }
    foreach ($z in $zoneRows) {
        if ($z.Type -eq 'Primary' -and "$($z.DynamicUpdate)" -eq 'NonsecureAndSecure' -and -not $z.Reverse) { Write-Status WARN "Zone $($z.Zone) allows NONSECURE dynamic updates" }
        if ($z.Type -eq 'Primary' -and -not $z.ADIntegrated) { Write-Status WARN "Zone $($z.Zone) is a file-backed primary (not AD-integrated)" }
    }
    if (-not ($zoneRows | Where-Object { $_.Reverse })) { Write-Status INFO 'No reverse lookup zones configured' }
    foreach ($cf in @($zoneRows | Where-Object { $_.Type -eq 'Forwarder' })) { Write-Status INFO "Conditional forwarder $($cf.Zone) -> $($cf.Masters)" }

    Write-Sub 'Scavenging'
    $anyScav = $false
    foreach ($ns in $dnsDCs) {
        $sc = Get-DnsServerScavenging -ComputerName $ns.HostName
        if ($sc.ScavengingState) {
            $anyScav = $true
            Write-Status PASS "$($ns.Name): scavenging enabled every $($sc.ScavengingInterval) (last run: $(Format-Date $sc.LastScavengeTime))"
        } else { Write-Status INFO "$($ns.Name): server scavenging disabled" }
    }
    $mainZone = $zoneRows | Where-Object { $_.Zone -eq $DomDNS } | Select-Object -First 1
    if (-not $anyScav) { Write-Status WARN 'No DNS server has scavenging enabled - stale records accumulate (enable on ONE DC + zone aging)' }
    elseif ($mainZone -and -not $mainZone.Aging) { Write-Status WARN "Scavenging is enabled on a server but aging is OFF on zone $DomDNS - nothing will be scavenged" }
} catch { if ("$($_.Exception.Message)" -ne 'skip') { Write-Status FAIL "Section error: $($_.Exception.Message)" } }

# ---------------------------------------------------------------------------------------------
Write-Section '8. DHCP'
try {
    if ($DhcpServers.Count -eq 0) {
        Write-Status INFO 'No AD-authorised Windows DHCP servers found - DHCP is likely on the firewall/router; review it there'
        throw 'skip'
    }
    foreach ($sk in $DhcpStale.Keys) {
        Write-Status WARN "DHCP server $($DhcpStale[$sk]) is authorised in AD but no longer resolves in DNS - stale authorisation (Remove-DhcpServerInDC)"
    }
    $seenScopes = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($key in @(@($DhcpData.Keys) + @($DhcpErr.Keys) | Select-Object -Unique)) {
        Write-Sub "DHCP server: $key"
        if ($DhcpPing.ContainsKey($key)) {
            if ($DhcpPing[$key]) { Write-Status PASS "$key responds to ping" } else { Write-Status FAIL "DHCP server $key does not respond to ping" }
        }
        $d = $DhcpData[$key]
        if (-not $d) { Write-Status WARN "Could not collect DHCP data from $($key): $(Limit-Text $DhcpErr[$key] 160)"; continue }

        if ($d.IsDC -and -not $d.DnsCredUser) { Write-Status WARN 'DHCP runs on a DC with no DNS dynamic-update credentials set (records get owned by the DC account; set a dedicated account)' }
        Write-Info "Server-level DNS option (006): $(if ($d.ServerOpt6) { $d.ServerOpt6 } else { '(none)' })"

        $scopeRows = foreach ($s in $d.Scopes) {
            $eff = $s.Opt6; if (-not $eff) { $eff = $d.ServerOpt6 }
            $rel = ($d.Failover | Where-Object { $_.Scopes -contains $s.ScopeId } | Select-Object -First 1).Name
            [pscustomobject]@{
                ScopeId  = $s.ScopeId
                Name     = Limit-Text $s.Name 25
                Range    = $s.Range
                State    = $s.State
                InUse    = $s.InUse
                Free     = $s.Free
                'Use%'   = $s.PctInUse
                Lease    = $s.Lease
                DNS006   = $eff
                Failover = $rel
            }
        }
        Show-Table $scopeRows -Flag {
            param($row)
            if ("$($row.State)" -ne 'Active') { return }
            if ($row.'Use%' -ge $ScopeFailPct) { 'FAIL' } elseif ($row.'Use%' -ge $ScopeWarnPct -or -not $row.DNS006) { 'WARN' }
        }

        foreach ($s in $scopeRows) {
            if ($s.State -ne 'Active') { Write-Status INFO "Scope $($s.ScopeId) is $($s.State)"; continue }
            if ($seenScopes.Add($s.ScopeId)) {
                if ($s.'Use%' -ge $ScopeFailPct) { Write-Status FAIL "Scope $($s.ScopeId) ($($s.Name)) is $($s.'Use%')% used ($($s.Free) free)" }
                elseif ($s.'Use%' -ge $ScopeWarnPct) { Write-Status WARN "Scope $($s.ScopeId) ($($s.Name)) is $($s.'Use%')% used ($($s.Free) free)" }
            }
            if (-not $s.DNS006) { Write-Status WARN "Scope $($s.ScopeId) hands out no DNS servers (option 006)" }
            else {
                $nonDc = @(($s.DNS006 -split ',') | Where-Object { $_ -and $_ -notin $DcIPs })
                if ($nonDc) { Write-Status WARN "Scope $($s.ScopeId) hands out non-DC DNS server(s) $($nonDc -join ', ') - domain clients need AD DNS" }
            }
        }
        if (-not $d.Failover) { Write-Status INFO 'No DHCP failover relationships on this server' }
    }

    Write-Sub 'Failover relationships and configuration sync'
    $processed = New-Object 'System.Collections.Generic.HashSet[string]'
    $anyRel = $false
    foreach ($key in @($DhcpData.Keys)) {
        $d = $DhcpData[$key]
        foreach ($rel in $d.Failover) {
            $anyRel = $true
            if (-not $processed.Add($rel.Name)) { continue }
            $modeTxt = "$($rel.Mode)"; if ($rel.Mode -eq 'LoadBalance') { $modeTxt += " $($rel.LoadBalance)%" } else { $modeTxt += " ($($rel.Role))" }
            if ($rel.State -eq 'Normal') { Write-Status PASS "Failover '$($rel.Name)': $key <-> $($rel.Partner), $modeTxt, state Normal" }
            else { Write-Status FAIL "Failover '$($rel.Name)': $key <-> $($rel.Partner), $modeTxt, state $($rel.State)" }

            $pk = Get-ShortName $rel.Partner
            $p = $DhcpData[$pk]
            if (-not $p) { Write-Status WARN "Failover '$($rel.Name)': could not read partner $($rel.Partner) to compare config"; continue }
            $prel = $p.Failover | Where-Object { $_.Name -eq $rel.Name } | Select-Object -First 1
            if (-not $prel) { Write-Status FAIL "Failover '$($rel.Name)' does not exist on partner $($rel.Partner)"; continue }
            if ((@($rel.Scopes | Sort-Object) -join ',') -ne (@($prel.Scopes | Sort-Object) -join ',')) {
                Write-Status FAIL "Failover '$($rel.Name)': scope lists differ ($($key): $($rel.Scopes -join ',') / partner: $($prel.Scopes -join ','))"
            }
            $okCount = 0
            foreach ($sid in $rel.Scopes) {
                $a = $d.Scopes | Where-Object { $_.ScopeId -eq $sid } | Select-Object -First 1
                $b = $p.Scopes | Where-Object { $_.ScopeId -eq $sid } | Select-Object -First 1
                if (-not $a -or -not $b) { Write-Status FAIL "Scope $sid missing on one failover partner"; continue }
                $diffs = @()
                foreach ($prop in 'Range', 'Mask', 'Lease', 'State', 'Options', 'Exclusions') {
                    if ("$($a.$prop)" -ne "$($b.$prop)") { $diffs += $prop }
                }
                $ra = @($a.Reservations | Where-Object { $_ }); $rb = @($b.Reservations | Where-Object { $_ })
                $resDiff = 0
                if ($ra.Count -and $rb.Count) { $resDiff = @(Compare-Object -ReferenceObject $ra -DifferenceObject $rb).Count }
                else { $resDiff = $ra.Count + $rb.Count }
                if ($resDiff) { $diffs += "Reservations ($resDiff differ)" }
                if ($diffs) { Write-Status WARN "Scope $sid out of sync between $key and $pk : $($diffs -join ', ') - run Invoke-DhcpServerv4FailoverReplication" }
                else { $okCount++ }
            }
            if ($okCount -gt 0) { Write-Status PASS "Failover '$($rel.Name)': $okCount scope(s) identical on both partners (range, options, exclusions, reservations)" }
        }
    }
    if (-not $anyRel -and $DhcpData.Count -eq 1) { Write-Status WARN 'Single Windows DHCP server with no failover - DHCP is a single point of failure' }
} catch { if ("$($_.Exception.Message)" -ne 'skip') { Write-Status FAIL "Section error: $($_.Exception.Message)" } }

# ---------------------------------------------------------------------------------------------
Write-Section '9. AD BACKUPS (last AD-aware backup per partition)'
try {
    $bk = foreach ($nc in $RootDSE.namingContexts) {
        $t = $null; $by = ''
        try {
            $md = Get-ADReplicationAttributeMetadata -Object $nc -Server $PDC -Properties dSASignature | Select-Object -First 1
            $t = $md.LastOriginatingChangeTime
            if ("$($md.LastOriginatingChangeDirectoryServerIdentity)" -match 'CN=NTDS Settings,CN=([^,]+)') { $by = $Matches[1] }
        } catch { }
        [pscustomobject]@{ Partition = $nc; LastBackup = (Format-Date $t); AgeDays = (Get-AgeDays $t); BackedUpOn = $by }
    }
    Show-Table $bk -Flag { param($row) if ($null -eq $row.AgeDays -or $row.AgeDays -gt 7) { 'FAIL' } elseif ($row.AgeDays -gt 2) { 'WARN' } }
    Write-Status INFO 'This date only moves when an AD-aware (system state / VSS) backup runs. Hypervisor snapshots and plain image copies do not update it, and it does not prove a restore works.'
    foreach ($b in $bk) {
        if ($null -eq $b.AgeDays) { Write-Status FAIL "No backup record for $($b.Partition)" }
        elseif ($b.AgeDays -gt 7) { Write-Status FAIL "$($b.Partition) last AD-aware backup $($b.AgeDays) days ago - backups failing or not system-state/AD-aware" }
        elseif ($b.AgeDays -gt 2) { Write-Status WARN "$($b.Partition) last AD-aware backup $($b.AgeDays) days ago" }
    }
    if (-not ($bk | Where-Object { $null -eq $_.AgeDays -or $_.AgeDays -gt 2 })) { Write-Status PASS 'All partitions backed up within the last 2 days' }
} catch { Write-Status FAIL "Section error: $($_.Exception.Message)" }

# ---------------------------------------------------------------------------------------------
Write-Section "10. USER ACCOUNTS ADDED IN THE LAST $NewAccountDays DAYS  (validate with customer)"
try {
    $since = $Now.AddDays(-$NewAccountDays)
    $creators = @{}
    $logStarts = @()
    foreach ($dc in $DCs) {
        $f = $DCFacts[$dc.Name]; if (-not $f) { continue }
        if ($f.SecurityOldest) { $logStarts += "$($dc.Name) $($f.SecurityOldest.ToString('yyyy-MM-dd HH:mm'))" }
        foreach ($e in $f.Created4720) { if ($e.Target) { $creators[$e.Target.ToLower()] = $e.By } }
    }
    Write-Status INFO "'CreatedBy' comes from Security event 4720 and is only known for accounts created after the oldest event in each DC's log: $($logStarts -join '; ') (log size is checked in section 17)."

    $newUsers = @($AllUsers | Where-Object { $_.whenCreated -ge $since } | Sort-Object whenCreated)
    $script:NewUserCount = $newUsers.Count
    $script:NewUserNeverLogon = 0
    $rows = foreach ($u in $newUsers) {
        $priv = $PrivAccounts.ContainsKey($u.DistinguishedName)
        if (-not $u.LastLogonDate) { $script:NewUserNeverLogon++ }
        $by = $creators[$u.SamAccountName.ToLower()]; if (-not $by) { $by = '?' }
        [pscustomobject]@{
            Created    = $u.whenCreated.ToString('yyyy-MM-dd')
            Name       = Limit-Text $u.Name 28
            Sam        = $u.SamAccountName
            Enabled    = $u.Enabled
            LastLogon  = Format-Date $u.LastLogonDate
            CreatedBy  = $by
            Privileged = $priv
            OU         = Limit-Text (Get-OUPath $u.CanonicalName) 35
            Title_Desc = Limit-Text ($(if ($u.Title) { $u.Title } else { $u.Description })) 35
        }
    }
    Show-Table $rows -Flag { param($row) if ($row.Privileged -or ($row.Enabled -and "$($row.LastLogon)" -eq 'never')) { 'WARN' } }
    Write-Status INFO "$($newUsers.Count) user account(s) created since $(Format-Date $since)"
    foreach ($u in $newUsers) {
        if ($u.Enabled -and -not $u.LastLogonDate -and (Get-AgeDays $u.whenCreated) -gt 14) { Write-Status WARN "New account $($u.SamAccountName) is enabled but has never logged on (created $(Format-Date $u.whenCreated)) - confirm it is needed" }
        if ($u.Enabled -and $u.PasswordNeverExpires) { Write-Status WARN "New account $($u.SamAccountName) has 'password never expires' set" }
        if ($PrivAccounts.ContainsKey($u.DistinguishedName)) { Write-Status WARN "New account $($u.SamAccountName) is PRIVILEGED ($($PrivAccounts[$u.DistinguishedName] -join ', '))" }
    }

    Write-Sub "Computers added in the last $NewAccountDays days"
    Show-Table ($AllComputers | Where-Object { $_.whenCreated -ge $since } | Sort-Object whenCreated | ForEach-Object {
            [pscustomobject]@{ Created = $_.whenCreated.ToString('yyyy-MM-dd'); Name = $_.Name; OS = $_.OperatingSystem; Enabled = $_.Enabled; OU = Limit-Text (Get-OUPath $_.CanonicalName) 40 }
        })

    Write-Sub "Groups added in the last $NewAccountDays days"
    Show-Table (Get-ADGroup -LDAPFilter "(whenCreated>=$($since.ToUniversalTime().ToString('yyyyMMddHHmmss')).0Z)" -Properties 'whenCreated', 'Description' -Server $PDC | Sort-Object whenCreated | ForEach-Object {
            [pscustomobject]@{ Created = $_.whenCreated.ToString('yyyy-MM-dd'); Name = $_.Name; Scope = $_.GroupScope; Category = $_.GroupCategory; Description = Limit-Text $_.Description 40 }
        })
} catch { Write-Status FAIL "Section error: $($_.Exception.Message)" }

# ---------------------------------------------------------------------------------------------
Write-Section '11. PRIVILEGED / ADMIN-LEVEL ACCESS REVIEW'
try {
    foreach ($pg in $PrivGroups) {
        Write-Sub "$($pg.Name)  ($(@($pg.Members | ForEach-Object { $_.DN } | Select-Object -Unique).Count) effective member(s), nested groups expanded)"
        $rows = foreach ($m in $pg.Members) {
            $obj = $UserByDN[$m.DN]; if (-not $obj) { $obj = $CompByDN[$m.DN] }
            $addedTxt = ''
            if ($m.Via -eq $pg.Name -and $pg.Added.ContainsKey($m.DN)) { $addedTxt = Format-Date $pg.Added[$m.DN] }
            [pscustomobject]@{
                Member  = Limit-Text $m.Name 30
                Sam     = $m.Sam
                Type    = $m.Class
                Enabled = $(if ($obj) { $obj.Enabled } else { '?' })
                Via     = Limit-Text $m.Via 50
                Added   = $addedTxt
            }
        }
        Show-Table $rows -Flag { param($row) if ("$($row.Enabled)" -eq 'False' -or "$($row.Type)" -eq 'unresolved') { 'WARN' } }
        if ($pg.ShouldBeEmpty -and @($pg.Members).Count -gt 0) {
            Write-Status WARN "$($pg.Name) has $(@($pg.Members).Count) member(s) - this group should normally be empty"
        }
        foreach ($k in $pg.Added.Keys) {
            $age = Get-AgeDays $pg.Added[$k]
            if ($null -ne $age -and $age -le $NewAccountDays) {
                Write-Status WARN "$($pg.Name): '$(($k -split ',')[0] -replace '^CN=','')' was added $(Format-Date $pg.Added[$k]) - validate with customer"
            }
        }
        foreach ($rm in $pg.Removed) {
            $age = Get-AgeDays $rm.Removed
            if ($null -ne $age -and $age -le $NewAccountDays) { Write-Status INFO "$($pg.Name): '$(($rm.Member -split ',')[0] -replace '^CN=','')' was removed $(Format-Date $rm.Removed)" }
        }
    }

    Write-Sub 'Privileged accounts - detail'
    $script:PrivAccountCount = 0; $script:PrivIssueCount = 0
    $privRows = @(); $privIssues = @()
    foreach ($dn in $PrivAccounts.Keys) {
        $u = $UserByDN[$dn]; $isComp = $false
        if (-not $u) { $u = $CompByDN[$dn]; if ($u) { $isComp = $true } }
        if (-not $u) {
            try { $u = Get-ADUser -Identity $dn -Server (Get-ServerForDN $dn) -Properties $UserProps } catch { }
        }
        if (-not $u) { continue }
        $script:PrivAccountCount++
        $pwdAge = Get-AgeDays $u.PasswordLastSet
        $bestLogon = Get-BestLogon $u
        $llAge  = Get-AgeDays $bestLogon
        $spn    = @($u.servicePrincipalName).Count -gt 0 -and -not $isComp
        $issues = @()
        if (-not $u.Enabled) { $issues += 'disabled but still in admin group' }
        elseif ($null -eq $llAge) { $issues += 'never logged on' }
        elseif ($llAge -gt $StaleDays) { $issues += "no logon in $llAge days" }
        if ($u.PasswordNeverExpires) { $issues += 'password never expires' }
        if ($null -ne $pwdAge -and $pwdAge -gt 365) { $issues += "password $pwdAge days old" }
        if ($spn) { $issues += 'has SPN (kerberoastable)' }
        if ($isComp -and -not $DCNameSet.Contains($u.Name)) { $issues += 'computer account in admin group' }
        if ($u.TrustedForDelegation -and -not $DCNameSet.Contains($u.Name)) { $issues += 'unconstrained delegation' }
        $privRows += [pscustomobject]@{
            Account     = $u.SamAccountName
            Name        = Limit-Text $u.Name 25
            Enabled     = $u.Enabled
            LastLogon   = Format-Date $bestLogon
            PwdAgeDays  = $pwdAge
            PwdNeverExp = $u.PasswordNeverExpires
            SPN         = $spn
            Sensitive   = $(if ($isComp) { '' } else { $u.AccountNotDelegated })
            Groups      = Limit-Text ($PrivAccounts[$dn] -join ', ') 60
        }
        if ($issues) { $script:PrivIssueCount++; $privIssues += "$($u.SamAccountName): $($issues -join '; ')" }
    }
    # Rows are marked when the account is disabled, stale, or kerberoastable; password age alone is listed below
    Show-Table ($privRows | Sort-Object Account) -Flag {
        param($row)
        if ("$($row.SPN)" -eq 'True') { 'FAIL' }
        elseif ("$($row.Enabled)" -eq 'False' -or "$($row.LastLogon)" -eq 'never') { 'WARN' }
        elseif ($null -ne $row.PwdAgeDays -and $row.PwdAgeDays -gt 365) { 'WARN' }
    }
    Write-Status INFO "$script:PrivAccountCount privileged account(s); $script:PrivIssueCount with findings. LastLogon is the newest value from any DC. 'Sensitive' = 'Account is sensitive and cannot be delegated' (recommended for admins)."
    foreach ($pi in $privIssues) { Write-Status WARN $pi }

    try {
        $pu = Get-ADGroup -Identity "$DomSID-525" -Server $PDC -Properties member
        $puNames = @(@($pu.member) | Where-Object { $_ } | ForEach-Object { ($_ -split ',')[0] -replace '^CN=', '' })
        Write-Status INFO "Protected Users group members: $(if ($puNames) { $puNames -join ', ' } else { '(none)' })"
    } catch { }

    Write-Sub 'Built-in and special accounts'
    $a500 = $AllUsers | Where-Object { $_.SID.Value -eq "$DomSID-500" } | Select-Object -First 1
    $a501 = $AllUsers | Where-Object { $_.SID.Value -eq "$DomSID-501" } | Select-Object -First 1
    $a502 = $AllUsers | Where-Object { $_.SID.Value -eq "$DomSID-502" } | Select-Object -First 1
    if ($a500) {
        $renamed = $(if ($a500.SamAccountName -ne 'Administrator') { "renamed to '$($a500.SamAccountName)'" } else { 'not renamed' })
        $a500Logon = Get-BestLogon $a500
        Write-Status INFO "Built-in Administrator: $renamed, enabled=$($a500.Enabled), last logon $(Format-Date $a500Logon), password age $(Get-AgeDays $a500.PasswordLastSet) days"
        $ll = Get-AgeDays $a500Logon
        if ($a500.Enabled -and $null -ne $ll -and $ll -le 30) { Write-Status WARN 'Built-in Administrator account is actively used - use named admin accounts instead (traceability)' }
        if ((Get-AgeDays $a500.PasswordLastSet) -gt 365) { Write-Status WARN "Built-in Administrator password is $(Get-AgeDays $a500.PasswordLastSet) days old" }
    }
    if ($a501) { if ($a501.Enabled) { Write-Status FAIL 'Guest account is ENABLED' } else { Write-Status PASS 'Guest account disabled' } }
    if ($a502) {
        $kAge = Get-AgeDays $a502.PasswordLastSet
        if ($kAge -gt 180) { Write-Status WARN "krbtgt password is $kAge days old (last set $(Format-Date $a502.PasswordLastSet)) - plan a krbtgt reset (twice, with replication in between)" }
        else { Write-Status PASS "krbtgt password age $kAge days" }
    }

    Write-Sub 'Orphaned adminCount=1 accounts (no longer privileged but still locked down by AdminSDHolder)'
    $orphans = @($AllUsers | Where-Object { $_.adminCount -eq 1 -and $_.SamAccountName -ne 'krbtgt' -and -not $PrivAccounts.ContainsKey($_.DistinguishedName) })
    Show-Table ($orphans | ForEach-Object { [pscustomobject]@{ Account = $_.SamAccountName; Name = $_.Name; Enabled = $_.Enabled; LastLogon = Format-Date $_.LastLogonDate } })
    if ($orphans) { Write-Status WARN "$($orphans.Count) account(s) with stale adminCount=1 - clear adminCount and re-enable ACL inheritance" }

    $hiddenPrimary = @($AllUsers | Where-Object { $_.primaryGroupID -and $_.primaryGroupID -ne 513 -and $_.primaryGroupID -ne 514 })
    foreach ($h in $hiddenPrimary) { Write-Status WARN "$($h.SamAccountName) has primary group RID $($h.primaryGroupID) (membership hidden from the 'member' attribute)" }
} catch { Write-Status FAIL "Section error: $($_.Exception.Message)" }

# ---------------------------------------------------------------------------------------------
Write-Section '12. ACCOUNT HYGIENE'
try {
    $cut = $Now.AddDays(-$StaleDays)
    $staleUsers = @($AllUsers | Where-Object { $_.Enabled -and $_.whenCreated -lt $cut -and (-not $_.LastLogonDate -or $_.LastLogonDate -lt $cut) } | Sort-Object LastLogonDate)
    Write-Sub "Enabled users with no logon in $StaleDays+ days ($($staleUsers.Count))"
    Show-Table ($staleUsers | ForEach-Object { [pscustomobject]@{ Account = $_.SamAccountName; Name = Limit-Text $_.Name 28; LastLogon = Format-Date $_.LastLogonDate; Created = Format-Date $_.whenCreated; OU = Limit-Text (Get-OUPath $_.CanonicalName) 40; Description = Limit-Text $_.Description 30 } })
    if ($staleUsers) { Write-Status WARN "$($staleUsers.Count) enabled user(s) inactive $StaleDays+ days (includes service accounts - review before disabling)" } else { Write-Status PASS 'No stale enabled users' }

    Write-Status INFO 'Last logon in these lists is the replicated value, which can lag the real logon by up to 14 days.'

    # A computer counts as stale only when its logon AND its machine-password change are both old
    $staleComps = @($AllComputers | Where-Object {
            $_.Enabled -and -not $DCNameSet.Contains($_.Name) -and $_.Name -ne 'AZUREADSSOACC' -and $_.whenCreated -lt $cut -and
            (-not $_.LastLogonDate -or $_.LastLogonDate -lt $cut) -and (-not $_.PasswordLastSet -or $_.PasswordLastSet -lt $cut)
        } | Sort-Object LastLogonDate)
    Write-Sub "Enabled computers with no logon in $StaleDays+ days ($($staleComps.Count))"
    Show-Table ($staleComps | ForEach-Object { [pscustomobject]@{ Computer = $_.Name; OS = $_.OperatingSystem; LastLogon = Format-Date $_.LastLogonDate; OU = Limit-Text (Get-OUPath $_.CanonicalName) 40 } })
    if ($staleComps) { Write-Status WARN "$($staleComps.Count) stale enabled computer object(s)" } else { Write-Status PASS 'No stale enabled computers' }

    $pne = @($AllUsers | Where-Object { $_.Enabled -and $_.PasswordNeverExpires })
    Write-Sub "Enabled users with 'password never expires' ($($pne.Count))"
    Show-Table ($pne | Sort-Object SamAccountName | ForEach-Object { [pscustomobject]@{ Account = $_.SamAccountName; Name = Limit-Text $_.Name 28; PwdAgeDays = Get-AgeDays $_.PasswordLastSet; LastLogon = Format-Date $_.LastLogonDate; Description = Limit-Text $_.Description 40 } })
    if ($pne) { Write-Status WARN "$($pne.Count) enabled account(s) with non-expiring passwords" }

    Write-Sub 'Risky account flags'
    $flagChecks = @(
        @{ Label = 'Password not required (PASSWD_NOTREQD)';             Set = @($AllUsers | Where-Object { $_.Enabled -and $_.PasswordNotRequired }); Sev = 'WARN' }
        @{ Label = 'Reversible password encryption';                       Set = @($AllUsers | Where-Object { $_.Enabled -and $_.AllowReversiblePasswordEncryption }); Sev = 'FAIL' }
        @{ Label = 'Kerberos pre-auth not required (AS-REP roastable)';    Set = @($AllUsers | Where-Object { $_.Enabled -and $_.DoesNotRequirePreAuth }); Sev = 'FAIL' }
        @{ Label = 'DES-only Kerberos';                                    Set = @($AllUsers | Where-Object { $_.Enabled -and $_.UseDESKeyOnly }); Sev = 'WARN' }
        @{ Label = 'Users with unconstrained delegation';                  Set = @($AllUsers | Where-Object { $_.Enabled -and $_.TrustedForDelegation }); Sev = 'FAIL' }
        @{ Label = 'Non-DC computers with unconstrained delegation';       Set = @($AllComputers | Where-Object { $_.Enabled -and $_.TrustedForDelegation -and -not $DCNameSet.Contains($_.Name) }); Sev = 'WARN' }
        @{ Label = 'Accounts trusted to auth for delegation (protocol transition)'; Set = @(@($AllUsers) + @($AllComputers) | Where-Object { $_.Enabled -and $_.TrustedToAuthForDelegation }); Sev = 'INFO' }
    )
    foreach ($fc in $flagChecks) {
        if ($fc.Set.Count -eq 0) { Write-Status PASS "$($fc.Label): none" }
        else { Write-Status $fc.Sev "$($fc.Label): $(($fc.Set | ForEach-Object { $_.SamAccountName }) -join ', ')" }
    }

    $kerb = @($AllUsers | Where-Object { $_.Enabled -and @($_.servicePrincipalName).Count -gt 0 -and $_.SamAccountName -ne 'krbtgt' })
    Write-Sub "User accounts with SPNs - kerberoastable ($($kerb.Count))"
    Show-Table ($kerb | ForEach-Object { [pscustomobject]@{ Account = $_.SamAccountName; PwdAgeDays = Get-AgeDays $_.PasswordLastSet; Privileged = $PrivAccounts.ContainsKey($_.DistinguishedName); SPNs = Limit-Text (@($_.servicePrincipalName) -join ', ') 70 } }) -Flag {
        param($row)
        if ($row.Privileged) { 'FAIL' } elseif ($null -ne $row.PwdAgeDays -and $row.PwdAgeDays -gt 365) { 'WARN' }
    }
    foreach ($k in $kerb) {
        if ($PrivAccounts.ContainsKey($k.DistinguishedName)) { Write-Status FAIL "Privileged account $($k.SamAccountName) has an SPN: any domain user can request its ticket and crack the password offline. Remove the SPN or move the service to its own account" }
    }
    foreach ($k in $kerb) { if ((Get-AgeDays $k.PasswordLastSet) -gt 365) { Write-Status WARN "Service account $($k.SamAccountName) has an SPN and a $(Get-AgeDays $k.PasswordLastSet)-day-old password (consider gMSA or long random password)" } }

    $maq = (Get-ADObject -Identity $Domain.DistinguishedName -Properties 'ms-DS-MachineAccountQuota' -Server $PDC).'ms-DS-MachineAccountQuota'
    if ($maq -gt 0) { Write-Status WARN "ms-DS-MachineAccountQuota is $maq - any authenticated user can join up to $maq computers (set to 0 and delegate joins)" }
    else { Write-Status PASS 'ms-DS-MachineAccountQuota is 0' }
} catch { Write-Status FAIL "Section error: $($_.Exception.Message)" }

# ---------------------------------------------------------------------------------------------
Write-Section '13. PASSWORD POLICY & LAPS'
try {
    $pp = Get-ADDefaultDomainPasswordPolicy -Server $PDC
    Write-Info "Default domain policy: min length $($pp.MinPasswordLength), complexity $($pp.ComplexityEnabled), history $($pp.PasswordHistoryCount), max age $($pp.MaxPasswordAge.Days)d, min age $($pp.MinPasswordAge.Days)d, lockout threshold $($pp.LockoutThreshold), lockout duration $($pp.LockoutDuration.TotalMinutes)m"
    if ($pp.MinPasswordLength -lt 8) { Write-Status FAIL "Minimum password length is $($pp.MinPasswordLength)" }
    elseif ($pp.MinPasswordLength -lt 12) { Write-Status WARN "Minimum password length is $($pp.MinPasswordLength) (12-14+ recommended)" }
    else { Write-Status PASS "Minimum password length $($pp.MinPasswordLength)" }
    if (-not $pp.ComplexityEnabled -and $pp.MinPasswordLength -lt 14) { Write-Status WARN 'Password complexity disabled with a short minimum length' }
    if ($pp.LockoutThreshold -eq 0) { Write-Status WARN 'No account lockout threshold (unlimited password guessing)' } else { Write-Status PASS "Account lockout after $($pp.LockoutThreshold) attempts" }
    if ($pp.ReversibleEncryptionEnabled) { Write-Status FAIL 'Domain policy stores passwords with reversible encryption' }

    $fgpp = @(Get-ADFineGrainedPasswordPolicy -Filter * -Server $PDC)
    if ($fgpp) {
        Write-Sub 'Fine-grained password policies'
        Show-Table ($fgpp | ForEach-Object { [pscustomobject]@{ Name = $_.Name; Precedence = $_.Precedence; MinLength = $_.MinPasswordLength; MaxAgeDays = $_.MaxPasswordAge.Days; Lockout = $_.LockoutThreshold; AppliesTo = (@($_.AppliesTo) | ForEach-Object { ($_ -split ',')[0] -replace '^CN=', '' }) -join ', ' } })
    }

    Write-Sub 'LAPS coverage (enabled, active, non-DC Windows computers)'
    $lapsTargets = @($AllComputers | Where-Object { $_.Enabled -and -not $DCNameSet.Contains($_.Name) -and $_.OperatingSystem -match 'Windows' -and $_.LastLogonDate -and $_.LastLogonDate -ge $Now.AddDays(-$StaleDays) })
    if (-not $HasLegacyLaps -and -not $HasWinLaps) {
        Write-Status WARN 'LAPS schema not present - local administrator passwords are not managed (likely shared across machines)'
    } else {
        $winL = 0; $legL = 0; $none = @()
        foreach ($c in $lapsTargets) {
            $w = $HasWinLaps -and $c.'msLAPS-PasswordExpirationTime'
            $l = $HasLegacyLaps -and $c.'ms-Mcs-AdmPwdExpirationTime'
            if ($w) { $winL++ } elseif ($l) { $legL++ } else { $none += $c.Name }
        }
        $total = [math]::Max($lapsTargets.Count, 1)
        $pct = [math]::Round(100 * ($winL + $legL) / $total, 0)
        Write-Info "Schema: Windows LAPS=$HasWinLaps, legacy LAPS=$HasLegacyLaps   |   Windows LAPS: $winL   Legacy LAPS: $legL   None: $($none.Count)   of $($lapsTargets.Count)  ($pct% covered)"
        if ($pct -lt 90) { Write-Status WARN "LAPS coverage $pct% - missing on: $(Limit-Text ($none -join ', ') 400)" } else { Write-Status PASS "LAPS coverage $pct%" }
        if ($none.Count -gt 0 -and $HasWinLaps) { Write-Status INFO 'Computers that back up Windows LAPS to Entra ID only have no AD attribute and are counted as None here - check those in Entra' }
        if ($legL -gt 0) { Write-Status INFO "$legL computer(s) still on legacy Microsoft LAPS - plan migration to Windows LAPS" }
    }
} catch { Write-Status FAIL "Section error: $($_.Exception.Message)" }

# ---------------------------------------------------------------------------------------------
Write-Section '14. GROUP POLICY'
try {
    if (-not (Get-Module -ListAvailable -Name GroupPolicy)) { Write-Status WARN 'GroupPolicy module not available - section skipped'; throw 'skip' }
    Import-Module GroupPolicy
    $gpos = @(Get-GPO -All -Domain $DomDNS -Server $PDC)
    $gpoRows = foreach ($g in $gpos) {
        $links = @(); $hasC = $false; $hasU = $false
        try {
            [xml]$x = Get-GPOReport -Guid $g.Id -ReportType Xml -Domain $DomDNS -Server $PDC
            $links = @($x.GPO.LinksTo | Where-Object { $_ })
            $hasC = [bool]$x.GPO.Computer.ExtensionData
            $hasU = [bool]$x.GPO.User.ExtensionData
        } catch { }
        $enabledLinks = @($links | Where-Object { "$($_.Enabled)" -eq 'true' })
        $verOk = ($g.Computer.DSVersion -eq $g.Computer.SysvolVersion) -and ($g.User.DSVersion -eq $g.User.SysvolVersion)
        [pscustomobject]@{
            Name      = Limit-Text $g.DisplayName 45
            Status    = "$($g.GpoStatus)"
            Links     = "$($enabledLinks.Count)/$($links.Count)"
            Settings  = (@($(if ($hasC) { 'C' }), $(if ($hasU) { 'U' })) | Where-Object { $_ }) -join '+'
            Modified  = $g.ModificationTime.ToString('yyyy-MM-dd')
            VersionOK = $verOk
            LinkedTo  = Limit-Text ((@($links | ForEach-Object { $_.SOMPath })) -join '; ') 60
            _Id       = "{$($g.Id.ToString().ToUpper())}"
            _Full     = $g.DisplayName
            _Enabled  = $enabledLinks.Count
        }
    }
    Show-Table ($gpoRows | Sort-Object Name | Select-Object -Property 'Name', 'Status', 'Links', 'Settings', 'Modified', 'VersionOK', 'LinkedTo') -Flag {
        param($row)
        if ("$($row.VersionOK)" -eq 'False' -or "$($row.Links)" -like '0/*') { 'WARN' }
    }
    Write-Status INFO "$($gpos.Count) GPOs"

    $unlinked = @($gpoRows | Where-Object { $_._Enabled -eq 0 })
    if ($unlinked) { Write-Status WARN "$($unlinked.Count) GPO(s) not linked anywhere (or all links disabled): $(($unlinked | ForEach-Object { $_._Full }) -join '; ')" }
    $empty = @($gpoRows | Where-Object { -not $_.Settings })
    if ($empty) { Write-Status INFO "$($empty.Count) empty GPO(s): $(($empty | ForEach-Object { $_._Full }) -join '; ')" }
    foreach ($g in @($gpoRows | Where-Object { -not $_.VersionOK })) { Write-Status WARN "GPO '$($g._Full)' AD and SYSVOL versions differ (replication issue or mid-edit)" }
    foreach ($g in @($gpoRows | Where-Object { $_.Status -eq 'AllSettingsDisabled' })) { Write-Status INFO "GPO '$($g._Full)' has all settings disabled" }

    foreach ($wk in '{31B2F340-016D-11D2-945F-00C04FB984F9}', '{6AC1786C-016F-11D2-945F-00C04FB984F9}') {
        if ($wk -notin $gpoRows._Id) { Write-Status FAIL "Well-known GPO $wk (Default Domain / Default Domain Controllers Policy) is missing" }
    }

    $policyPath = "\\$DomDNS\SYSVOL\$DomDNS\Policies"
    $guidRx = '^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$'
    $folders = @(Get-ChildItem -LiteralPath $policyPath -Directory | Where-Object { $_.Name -match $guidRx } | ForEach-Object { $_.Name.ToUpper() })
    $ids = @($gpoRows | ForEach-Object { $_._Id })
    $orphanFolders = @($folders | Where-Object { $_ -notin $ids })
    $missingFolders = @($gpoRows | Where-Object { $_._Id -notin $folders })
    if ($orphanFolders) { Write-Status WARN "Orphaned SYSVOL policy folder(s) with no GPO in AD: $($orphanFolders -join ', ')" }
    foreach ($m in $missingFolders) { Write-Status FAIL "GPO '$($m._Full)' has no folder in SYSVOL" }
    if (-not $orphanFolders -and -not $missingFolders) { Write-Status PASS 'Every GPO has a matching SYSVOL folder and vice versa' }
    if (Test-Path "$policyPath\PolicyDefinitions") { Write-Status PASS 'Central store (PolicyDefinitions) exists' } else { Write-Status INFO 'No ADMX central store in SYSVOL' }

    # Group Policy Preferences passwords: the "cpassword" value is encrypted with a key Microsoft published,
    # so any domain user can decrypt it. The value itself is never read into the report.
    Write-Sub 'Passwords stored in Group Policy Preferences'
    $gppNames = 'Groups.xml', 'Services.xml', 'ScheduledTasks.xml', 'DataSources.xml', 'Drives.xml', 'Printers.xml'
    $gppFiles = @(Get-ChildItem -Path $policyPath -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $gppNames -contains $_.Name })
    $gppHits = 0
    foreach ($gppFile in $gppFiles) {
        $gppMatch = Select-String -LiteralPath $gppFile.FullName -Pattern 'cpassword="[^"]+"' -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $gppMatch) { continue }
        $gppHits++
        $gppGuid = ''
        if ($gppFile.FullName -match '\{[0-9A-Fa-f-]{36}\}') { $gppGuid = $Matches[0].ToUpper() }
        $gppGpo = ($gpoRows | Where-Object { $_._Id -eq $gppGuid } | Select-Object -First 1)._Full
        if (-not $gppGpo) { $gppGpo = $gppGuid }
        Write-Status FAIL "GPO '$gppGpo' stores a password in $($gppFile.Name) (Group Policy Preferences). Any domain user can decrypt it: remove the setting and change that password"
    }
    if ($gppHits -eq 0) { Write-Status PASS "No Group Policy Preferences passwords found in SYSVOL ($($gppFiles.Count) preference file(s) checked)" }
} catch { if ("$($_.Exception.Message)" -ne 'skip') { Write-Status FAIL "Section error: $($_.Exception.Message)" } }

# ---------------------------------------------------------------------------------------------
Write-Section "15. OPERATING SYSTEM LIFECYCLE (enabled computers active in last $StaleDays days)"
try {
    $active = @($AllComputers | Where-Object { $_.Enabled -and $_.LastLogonDate -and $_.LastLogonDate -ge $Now.AddDays(-$StaleDays) })
    $withSupport = @(foreach ($c in $active) {
            [pscustomobject]@{ Name = $c.Name; OS = $c.OperatingSystem; Version = $c.OperatingSystemVersion; LastLogon = $c.LastLogonDate; Support = (Get-OSSupport $c.OperatingSystem $c.OperatingSystemVersion) }
        })
    Show-Table ($withSupport | Group-Object -Property 'OS', 'Support' | Sort-Object Count -Descending | ForEach-Object {
            $first = $_.Group[0]
            [pscustomobject]@{ OperatingSystem = $(if ($first.OS) { $first.OS } else { '(blank)' }); Builds = (@($_.Group | ForEach-Object { if ($_.Version -match '\((\d+)\)') { $Matches[1] } } | Select-Object -Unique) -join ','); Count = $_.Count; Support = $first.Support }
        }) -Flag { param($row) if ("$($row.Support)" -like 'EOL*') { 'FAIL' } elseif ("$($row.Support)" -ne 'Supported') { 'WARN' } }

    $eol = @($withSupport | Where-Object { $_.Support -like 'EOL*' })
    if ($eol) { Write-Status FAIL "$($eol.Count) active computer(s) on end-of-life OS: $(Limit-Text (($eol | ForEach-Object { "$($_.Name) ($($_.OS))" }) -join ', ') 500)" }
    $endingSoon = @($withSupport | Where-Object { $_.Support -like 'EOS *' })
    foreach ($group in ($endingSoon | Group-Object -Property 'OS', 'Support')) {
        $first = $group.Group[0]
        Write-Status WARN "$($group.Count) $($first.OS) machine(s) - support ends $($first.Support.Substring(4)): $(Limit-Text (($group.Group | ForEach-Object { $_.Name }) -join ', ') 300)"
    }
    # Only Windows 11 builds missing from the baseline table; other unlisted systems (NAS, Mac, Linux) stay table-only
    $review = @($withSupport | Where-Object { $_.Support -eq 'Review' -and $_.OS -match 'Windows 11' })
    if ($review) { Write-Status WARN "$($review.Count) Windows 11 computer(s) on a build this script has no support date for - check them by hand: $(Limit-Text (($review | ForEach-Object { "$($_.Name) ($($_.Version))" }) -join ', ') 300)" }
    $ltsc = @($withSupport | Where-Object { $_.Support -eq 'Check LTSC' })
    if ($ltsc) { Write-Status INFO "$($ltsc.Count) Windows LTSC/LTSB machine(s) - confirm LTSC version support dates" }
    if (-not $eol -and -not $endingSoon -and -not $review) { Write-Status PASS 'No active computers on end-of-life operating systems' }

    Write-Sub 'Servers'
    Show-Table ($withSupport | Where-Object { $_.OS -match 'Server' } | Sort-Object Name | ForEach-Object { [pscustomobject]@{ Server = $_.Name; OS = $_.OS; Build = $_.Version; LastLogon = Format-Date $_.LastLogon; Support = $_.Support } }) -Flag { param($row) if ("$($row.Support)" -like 'EOL*') { 'FAIL' } elseif ("$($row.Support)" -ne 'Supported') { 'WARN' } }
} catch { Write-Status FAIL "Section error: $($_.Exception.Message)" }

# ---------------------------------------------------------------------------------------------
Write-Section '16. PKI & ENTRA CONNECT'
try {
    Write-Sub 'Enterprise certificate authorities'
    if (-not $CAs) { Write-Status INFO 'No enterprise CA published in AD' }
    foreach ($ca in $CAs) {
        $certs = @()
        foreach ($bytes in @($ca.cACertificate)) {
            try { $certs += New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (, [byte[]]$bytes) } catch { }
        }
        $newest = $certs | Sort-Object NotAfter -Descending | Select-Object -First 1
        $reach = Test-Ping $ca.dNSHostName
        $onDc = $DCNameSet.Contains((Get-ShortName $ca.dNSHostName))
        if (-not $newest) { Write-Status WARN "CA '$($ca.Name)' on $($ca.dNSHostName): could not read CA certificate" }
        else {
            $days = [int]($newest.NotAfter - $Now).TotalDays
            $msg = "CA '$($ca.Name)' on $($ca.dNSHostName): certificate expires $(Format-Date $newest.NotAfter) ($days days)"
            if ($days -lt 0) { Write-Status FAIL $msg } elseif ($days -lt 180) { Write-Status WARN $msg } else { Write-Status PASS $msg }
        }
        if (-not $reach) { Write-Status WARN "CA host $($ca.dNSHostName) does not respond to ping" }
        if ($onDc) { Write-Status INFO "CA '$($ca.Name)' is installed on a domain controller (not best practice)" }
    }

    if ($CAs) {
        # Certificate templates that let a non-admin obtain a certificate they can log on with as someone else
        # (the "ESC" escalation paths). Only templates a CA actually publishes are checked.
        Write-Sub 'Certificate templates and CA settings (AD CS escalation paths)'
        $enrollGuid    = '0e10c968-78fb-11d2-90d4-00c04f79dc55'
        $logonEkus     = '1.3.6.1.5.5.7.3.2', '1.3.6.1.5.2.3.4', '1.3.6.1.4.1.311.20.2.2', '2.5.29.37.0'
        $publishedTemplates = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($ca in $CAs) {
            foreach ($templateName in @($ca.certificateTemplates)) { if ($templateName) { [void]$publishedTemplates.Add("$templateName") } }
        }
        $templates = @(Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigNC" -LDAPFilter '(objectClass=pKICertificateTemplate)' -Properties 'displayName', 'pKIExtendedKeyUsage', 'msPKI-Certificate-Name-Flag', 'msPKI-Enrollment-Flag', 'msPKI-RA-Signature', 'msPKI-Template-Schema-Version' -Server $PDC)
        $templateFindings = 0
        $templatesChecked = 0
        foreach ($tpl in $templates) {
            if (-not $publishedTemplates.Contains("$($tpl.Name)")) { continue }
            $templatesChecked++
            try {
            $tplAcl = Get-AdAcl -DN $tpl.DistinguishedName -Server $PDC
            $enrollers = @{}
            $editors   = @{}
            foreach ($rule in $tplAcl.Rules) {
                if ("$($rule.AccessControlType)" -ne 'Allow') { continue }
                $ruleSid   = "$($rule.IdentityReference.Value)"
                $ruleClass = Get-SidClass $ruleSid
                if ($ruleClass -eq 'Safe') { continue }
                $ruleRights = [int]$rule.ActiveDirectoryRights
                $fullControl = (($ruleRights -band $ADR.GenericAll) -eq $ADR.GenericAll)
                $hasExtended = (($ruleRights -band $ADR.ExtendedRight) -ne 0)
                $enrollScope = ($rule.ObjectType -eq $EmptyGuid) -or ("$($rule.ObjectType)" -eq $enrollGuid)
                if ($fullControl -or ($hasExtended -and $enrollScope)) { $enrollers[$ruleSid] = $ruleClass }
                $editRights = @(Get-DangerousRights $rule | Where-Object { $_ -ne 'all extended rights' })
                if ($editRights.Count -gt 0) { $editors[$ruleSid] = $ruleClass }
            }

            $ekus = @($tpl.pKIExtendedKeyUsage | Where-Object { $_ } | ForEach-Object { "$_" })
            $nameFlag = [int64]0; $enrollFlag = [int64]0; $raSignatures = 0; $schemaVersion = 0
            if ($null -ne $tpl.'msPKI-Certificate-Name-Flag') { $nameFlag = [int64]$tpl.'msPKI-Certificate-Name-Flag' }
            if ($null -ne $tpl.'msPKI-Enrollment-Flag') { $enrollFlag = [int64]$tpl.'msPKI-Enrollment-Flag' }
            if ($null -ne $tpl.'msPKI-RA-Signature') { $raSignatures = [int]$tpl.'msPKI-RA-Signature' }
            if ($null -ne $tpl.'msPKI-Template-Schema-Version') { $schemaVersion = [int]$tpl.'msPKI-Template-Schema-Version' }
            $requesterSetsSubject = (($nameFlag -band 1) -ne 0)
            $needsApproval        = (($enrollFlag -band 2) -ne 0)
            $noSecurityExtension  = (($enrollFlag -band 524288) -ne 0)
            $noGate               = (-not $needsApproval) -and ($raSignatures -eq 0)
            $logonCapable         = ($ekus.Count -eq 0) -or (@($ekus | Where-Object { $logonEkus -contains $_ }).Count -gt 0)
            $anyPurpose           = ($ekus.Count -eq 0) -or ($ekus -contains '2.5.29.37.0')
            $enrollmentAgent      = ($ekus -contains '1.3.6.1.4.1.311.20.2.1')
            $serverAuth           = ($ekus -contains '1.3.6.1.5.5.7.3.1')

            $problems = @()
            if ($noGate -and $requesterSetsSubject -and $logonCapable) { $problems += 'ESC1 - the requester chooses the subject name and the certificate can be used to log on' }
            elseif ($noGate -and $anyPurpose) { $problems += 'ESC2 - any-purpose certificate issued without approval' }
            if ($noGate -and $enrollmentAgent) { $problems += 'ESC3 - enrollment agent certificate issued without approval' }
            if ($noSecurityExtension -and $logonCapable) { $problems += 'ESC9 - the security extension is switched off on a logon-capable template' }
            if ($schemaVersion -eq 1 -and $requesterSetsSubject) { $problems += 'ESC15 - version 1 template where the requester chooses the subject (the CA needs the November 2024 update)' }
            if ($noGate -and $requesterSetsSubject -and $serverAuth -and -not $logonCapable) { $problems += 'ESC17 (community-defined, not a Microsoft ESC) - the requester chooses the subject on a server-authentication template' }

            if ($problems.Count -gt 0 -and $enrollers.Count -gt 0) {
                $templateFindings++
                $severity = 'WARN'
                if (@($enrollers.Values) -contains 'Unsafe') { $severity = 'FAIL' }
                $enrollerNames = ($enrollers.Keys | ForEach-Object { Resolve-SidName $_ }) -join ', '
                Write-Status $severity "Template '$($tpl.Name)' - $($problems -join '; '). Can be enrolled by $enrollerNames"
            }
            foreach ($editorSid in $editors.Keys) {
                $templateFindings++
                $severity = 'WARN'
                if ($editors[$editorSid] -eq 'Unsafe') { $severity = 'FAIL' }
                Write-Status $severity "Template '$($tpl.Name)' - ESC4: '$(Resolve-SidName $editorSid)' can change the template itself"
            }
            if ($tplAcl.Owner -and (Get-SidClass $tplAcl.Owner) -ne 'Safe') {
                $templateFindings++
                Write-Status WARN "Template '$($tpl.Name)' - ESC4: owned by '$(Resolve-SidName $tplAcl.Owner)', who can change its permissions"
            }
            } catch { $templateFindings++; Write-Status WARN "Template '$($tpl.Name)' could not be checked - $($_.Exception.Message)" }
        }
        if ($templateFindings -eq 0) { Write-Status PASS "No risky settings or permissions on the $templatesChecked published certificate template(s)" }

        foreach ($ca in $CAs) {
            $caLabel  = "CA '$($ca.Name)'"
            $caConfig = '"' + "$($ca.dNSHostName)\$($ca.Name)" + '"'
            try {
                $editFlags = (Invoke-Native -Exe 'certutil.exe' -Arguments @('-config', $caConfig, '-getreg', 'policy\EditFlags') -TimeoutSec 30) -join ' '
                if ($editFlags -notmatch 'EditFlags REG_DWORD') {
                    Write-Status INFO "$caLabel - could not read the CA policy settings remotely (certutil). Check ESC6, ESC11 and ESC16 on the CA itself"
                } else {
                    if ($editFlags -match 'EDITF_ATTRIBUTESUBJECTALTNAME2') { Write-Status FAIL "$caLabel - ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 is set, so any requester can add another user's name to a certificate" }
                    else { Write-Status PASS "$caLabel - requesters cannot add their own subject alternative name (ESC6 not present)" }
                    $interfaceFlags = (Invoke-Native -Exe 'certutil.exe' -Arguments @('-config', $caConfig, '-getreg', 'CA\InterfaceFlags') -TimeoutSec 30) -join ' '
                    if ($interfaceFlags -match 'InterfaceFlags REG_DWORD' -and $interfaceFlags -notmatch 'IF_ENFORCEENCRYPTICERTREQUEST') { Write-Status WARN "$caLabel - ESC11: RPC certificate requests are not required to be encrypted (relay risk)" }
                    $disabledExtensions = (Invoke-Native -Exe 'certutil.exe' -Arguments @('-config', $caConfig, '-getreg', 'policy\DisableExtensionList') -TimeoutSec 30) -join ' '
                    if ($disabledExtensions -match '1\.3\.6\.1\.4\.1\.311\.25\.2') { Write-Status FAIL "$caLabel - ESC16: the security extension is disabled for every certificate this CA issues" }
                    $auditFilter = (Invoke-Native -Exe 'certutil.exe' -Arguments @('-config', $caConfig, '-getreg', 'CA\AuditFilter') -TimeoutSec 30) -join ' '
                    if ($auditFilter -match 'AuditFilter REG_DWORD = ([0-9a-fA-F]+)') {
                        if ([Convert]::ToInt32($Matches[1], 16) -ne 127) { Write-Status WARN "$caLabel - CA auditing is not fully enabled (AuditFilter is 0x$($Matches[1]), expected 0x7f)" }
                    }
                }
            } catch { Write-Status INFO "$caLabel - could not query the CA with certutil ($($_.Exception.Message))" }

            $httpEnrollment = @($ca.'msPKI-Enrollment-Servers' | Where-Object { "$_" -match 'http://' })
            if ($httpEnrollment.Count -gt 0) { Write-Status FAIL "$caLabel - ESC8: a certificate enrollment web service is published over plain HTTP" }
            try {
                $webEnrollment = Invoke-OnComputer -ComputerName $ca.dNSHostName -ScriptBlock { [bool](Get-WindowsFeature -Name ADCS-Web-Enrollment -ErrorAction SilentlyContinue).Installed } -TimeoutSec 60
                if ($webEnrollment) { Write-Status WARN "$caLabel - ESC8: web enrollment (/certsrv) is installed. Confirm it is HTTPS-only with Extended Protection, or remove it" }
            } catch { }
        }
    }

    Write-Sub 'Entra Connect (directory sync)'
    if (-not $SyncServers -and -not $CloudSyncGmsa) { Write-Status INFO 'No Entra Connect (MSOL_) account or Cloud Sync gMSA found. If Entra Connect uses a custom AD DS connector account, check it by hand' }
    foreach ($s in $SyncServers) {
        Write-Info "Sync account $($s.Account): server '$($s.Server)', tenant '$($s.Tenant)', enabled=$($s.Enabled), created $(Format-Date $s.Created), last logon $(Format-Date $s.LastLogon)"
        $llAge = Get-AgeDays $s.LastLogon
        if ($s.Enabled -and $null -eq $llAge) { Write-Status WARN "$($s.Account) has never logged on - leftover from an old Entra Connect install?" }
        elseif ($s.Enabled -and $llAge -gt 30) { Write-Status WARN "$($s.Account) has not logged on in $llAge days - leftover from an old Entra Connect install?" }
    }
    if (@($SyncServers | Where-Object { $_.Enabled }).Count -gt 1) { Write-Status INFO 'Multiple MSOL_ accounts - expected only if a staging server exists; otherwise remove leftovers' }

    $syncCollector = {
        $ErrorActionPreference = 'SilentlyContinue'
        $o = [ordered]@{ Service = "$((Get-Service -Name ADSync).Status)"; Version = ''; SyncEnabled = $null; Staging = $null; NextUtc = $null; Interval = ''; LastRun = $null; LastResult = ''; LastProfile = ''; AutoUpgrade = ''; AuthType = '' }
        # The install path comes from the service, so a custom install folder still works
        $exePath = "$((Get-CimInstance -ClassName Win32_Service -Filter "Name='ADSync'").PathName)".Trim()
        if ($exePath -match '^"([^"]+)"') { $exePath = $Matches[1] } elseif ($exePath -match '^(\S+\.exe)') { $exePath = $Matches[1] }
        if (-not $exePath) { $exePath = Join-Path $env:ProgramFiles 'Microsoft Azure AD Sync\Bin\miiserver.exe' }
        $exe = Get-Item -LiteralPath $exePath
        if ($exe) { $o.Version = $exe.VersionInfo.ProductVersion }
        Import-Module ADSync -ErrorAction Stop
        $sch = Get-ADSyncScheduler
        $o.SyncEnabled = $sch.SyncCycleEnabled; $o.Staging = $sch.StagingModeEnabled
        $o.NextUtc = $sch.NextSyncCycleStartTimeInUTC; $o.Interval = "$($sch.CurrentlyEffectiveSyncCycleInterval)"
        $last = Get-ADSyncRunProfileResult -NumberRequested 10 | Sort-Object StartDate -Descending | Select-Object -First 1
        if ($last) { $o.LastRun = $last.StartDate; $o.LastResult = "$($last.Result)"; $o.LastProfile = "$($last.RunProfileName) / $($last.ConnectorName)" }
        $o.AutoUpgrade = "$(Get-ADSyncAutoUpgrade)"
        # Reports how the server signs in to Entra ID (older builds do not have this cmdlet)
        $authText = (Get-ADSyncEntraConnectorCredential | Out-String)
        if ($authText) { $o.AuthType = ($authText -replace '\s+', ' ').Trim() }
        [pscustomobject]$o
    }
    foreach ($srvName in @($SyncServers | Where-Object { $_.Enabled -and $_.Server } | ForEach-Object { $_.Server } | Select-Object -Unique)) {
        $exists = $AllComputers | Where-Object { $_.Name -ieq $srvName -and $_.Enabled }
        $resolves = $true
        try { $null = [System.Net.Dns]::GetHostEntry($srvName) } catch { $resolves = $false }
        if (-not $exists -or -not $resolves) {
            Write-Status WARN "Entra Connect server $srvName no longer exists (no enabled computer object or DNS record) - its MSOL_ account is a leftover; remove it"
            continue
        }
        try {
            $sd = Invoke-OnComputer -ComputerName $srvName -ScriptBlock $syncCollector
            Write-Info "$srvName : ADSync service $($sd.Service), version $($sd.Version), sync enabled $($sd.SyncEnabled), staging $($sd.Staging), interval $($sd.Interval), next run (UTC) $($sd.NextUtc)"
            if ($sd.Service -ne 'Running') { Write-Status FAIL "$srvName : ADSync service is $($sd.Service)" }
            if ($sd.Staging) { Write-Status INFO "$srvName is in STAGING mode (not exporting)" }
            elseif ($sd.SyncEnabled -eq $false) { Write-Status FAIL "$srvName : sync scheduler is DISABLED" }
            $syncVersion = $null
            try { $syncVersion = [version]"$($sd.Version)" } catch { }
            $deadlineText = Format-Date $Baseline.EntraConnectDeadline
            $daysLeft = [int]($Baseline.EntraConnectDeadline - $Now).TotalDays
            if (-not $syncVersion) { Write-Status WARN "$srvName : could not read the Entra Connect version - confirm it is $($Baseline.EntraConnectMin) or later" }
            elseif ($syncVersion -lt $Baseline.EntraConnectMin) {
                $versionMsg = "$srvName : Entra Connect $syncVersion is below $($Baseline.EntraConnectMin). Microsoft requires that version or later, with application-based authentication, by $deadlineText ($daysLeft days) or sync stops"
                if ($daysLeft -le 60) { Write-Status FAIL $versionMsg } else { Write-Status WARN $versionMsg }
            } else { Write-Status PASS "$srvName : Entra Connect $syncVersion meets the $($Baseline.EntraConnectMin) minimum" }
            if ("$($sd.AuthType)" -match 'ServiceAccount') { Write-Status WARN "$srvName : still signs in to Entra ID with the legacy sync account. Switch to application-based authentication before $deadlineText (Connect wizard > Additional tasks)" }
            elseif ("$($sd.AuthType)" -match '\bApplication\b') { Write-Status PASS "$srvName : signs in to Entra ID with application-based authentication" }
            else { Write-Status INFO "$srvName : could not tell whether application-based authentication is configured - check it in the Connect wizard before $deadlineText" }
            if ("$($sd.AutoUpgrade)" -eq 'Suspended') { Write-Status WARN "$srvName : Entra Connect auto-upgrade is suspended" }
            elseif ($sd.AutoUpgrade) { Write-Status INFO "$srvName : Entra Connect auto-upgrade is $($sd.AutoUpgrade)" }
            if ($sd.LastRun) {
                $h = [math]::Round(($Now.ToUniversalTime() - $sd.LastRun.ToUniversalTime()).TotalHours, 1)
                $msg = "$srvName : last run $($sd.LastProfile) at $($sd.LastRun) - result '$($sd.LastResult)'"
                if ($sd.LastResult -ne 'success') { Write-Status WARN $msg }
                elseif ($h -gt 3 -and -not $sd.Staging) { Write-Status WARN "$msg ($h h ago)" }
                else { Write-Status PASS $msg }
            } else {
                Write-Status WARN "$srvName : could not read the last sync run (Get-ADSyncRunProfileResult returned nothing) - check the last run in Synchronization Service Manager"
            }
        } catch { Write-Status WARN "Could not query Entra Connect on $srvName ($($_.Exception.Message)) - check Synchronization Service Manager manually" }
    }
    if ($CloudSyncGmsa) { Write-Status INFO "Entra Cloud Sync agent account(s) present: $(($CloudSyncGmsa | ForEach-Object { $_.Name }) -join ', ') - check agent health in the Entra portal" }
} catch { Write-Status FAIL "Section error: $($_.Exception.Message)" }

# ---------------------------------------------------------------------------------------------
Write-Section '17. DC SECURITY HARDENING'
# Advanced audit subcategories every DC should record (matched by GUID first, English name second)
$AuditExpected = @(
    @{ Guid = '0CCE923F-69AE-11D9-BED3-505054503030'; Name = 'Credential Validation';              Need = 'Success and Failure' }
    @{ Guid = '0CCE9242-69AE-11D9-BED3-505054503030'; Name = 'Kerberos Authentication Service';    Need = 'Success and Failure' }
    @{ Guid = '0CCE9240-69AE-11D9-BED3-505054503030'; Name = 'Kerberos Service Ticket Operations'; Need = 'Success and Failure' }
    @{ Guid = '0CCE9215-69AE-11D9-BED3-505054503030'; Name = 'Logon';                              Need = 'Success and Failure' }
    @{ Guid = '0CCE921B-69AE-11D9-BED3-505054503030'; Name = 'Special Logon';                      Need = 'Success' }
    @{ Guid = '0CCE9235-69AE-11D9-BED3-505054503030'; Name = 'User Account Management';            Need = 'Success' }
    @{ Guid = '0CCE9236-69AE-11D9-BED3-505054503030'; Name = 'Computer Account Management';        Need = 'Success' }
    @{ Guid = '0CCE9237-69AE-11D9-BED3-505054503030'; Name = 'Security Group Management';          Need = 'Success' }
    @{ Guid = '0CCE923C-69AE-11D9-BED3-505054503030'; Name = 'Directory Service Changes';          Need = 'Success' }
    @{ Guid = '0CCE922F-69AE-11D9-BED3-505054503030'; Name = 'Audit Policy Change';                Need = 'Success' }
)
try {
    $patchFloor = Format-Date $Baseline.MinDcPatchDate
    foreach ($dc in $DCs) {
        $f = $DCFacts[$dc.Name]
        $tag = $dc.Name + ':'
        Write-Sub $dc.Name
        if (-not $f) { Write-Status WARN "$tag no data collected"; continue }

        try {
        # Patch floor: OS build and revision against the baseline build for this OS
        $patchVerdict = Get-PatchVerdict -Build $f.OsBuild -Ubr $f.OsUbr -LastPatch $f.LastPatch -PatchFloor $patchFloor
        Write-Status $patchVerdict.Status "$tag $($patchVerdict.Message)"

        # LDAP signing and channel binding
        $ldapCounts = @{}
        foreach ($ldapEvent in @($f.LdapEvents)) { if ($ldapEvent) { $ldapCounts[[int]$ldapEvent.Id] = [int]$ldapEvent.Count } }
        $unsignedSummaries = [int]$ldapCounts[2887]
        if ($f.LdapServerIntegrity -eq 2) {
            Write-Status PASS "$tag LDAP signing is required"
        } elseif ($unsignedSummaries -gt 0) {
            $bindDetail = 'event 2887 logged'
            if ($f.UnsignedBindSummary) { $bindDetail = "$($f.UnsignedBindSummary)" }
            Write-Status WARN "$tag LDAP signing is NOT required and clients still bind unsigned ($bindDetail). Find them with event 2889 logging, fix them, then require signing"
        } elseif ($null -eq $f.LdapServerIntegrity -and "$($dc.OperatingSystem)" -match '2025') {
            # Server 2025 enforces signing through a separate policy, so an unset LDAPServerIntegrity does not mean it is off
            Write-Status INFO "$tag LDAPServerIntegrity is not set. Server 2025 requires LDAP signing by default on new installs - confirm the 'LDAP server signing requirements Enforcement' policy is not Disabled"
        } else {
            Write-Status WARN "$tag LDAP signing is NOT required. No unsigned binds were logged in the last $EventDays days, so it looks ready to enforce"
        }
        $channelBinding = $f.LdapChannelBinding
        if ($channelBinding -eq 2) { Write-Status PASS "$tag LDAP channel binding is set to Always" }
        elseif ($channelBinding -eq 1) { Write-Status WARN "$tag LDAP channel binding is 'When supported' - move to Always once clients are confirmed" }
        else { Write-Status WARN "$tag LDAP channel binding is not enforced (LdapEnforceChannelBinding is not set or 0)" }
        $bindingAudit = [int]$ldapCounts[3039] + [int]$ldapCounts[3074] + [int]$ldapCounts[3075]
        if ($bindingAudit -gt 0) { Write-Status WARN "$tag $bindingAudit LDAP channel-binding event(s) in $EventDays days (3039/3074/3075) - those clients fail once binding is enforced" }

        # NTLM
        $lmLevel = $f.LmCompatibilityLevel
        if ($null -eq $lmLevel) { Write-Status WARN "$tag LmCompatibilityLevel is not set (default 3, so this DC still accepts LM and NTLMv1) - set it to 5" }
        elseif ($lmLevel -ge 5) { Write-Status PASS "$tag LmCompatibilityLevel is $lmLevel (NTLMv2 only)" }
        elseif ($lmLevel -ge 3) { Write-Status WARN "$tag LmCompatibilityLevel is $lmLevel, so this DC still accepts NTLMv1 - set it to 5" }
        else { Write-Status FAIL "$tag LmCompatibilityLevel is $lmLevel - this DC accepts LM and NTLMv1 and may send them - set it to 5" }
        $ntlmWindow = $EventDays
        if ($f.NtlmWindowDays) { $ntlmWindow = $f.NtlmWindowDays }
        if ([int]$f.NtlmV1Count -gt 0) { Write-Status FAIL "$tag $($f.NtlmV1Count) NTLMv1 logon(s) in the last $ntlmWindow day(s) - $(Limit-Text (@($f.NtlmV1Top) -join '; ') 400)" }
        elseif (Test-LogCoversWindow -Oldest $f.SecurityOldest -Days $ntlmWindow) { Write-Status PASS "$tag no NTLMv1 logons in the Security log (last $ntlmWindow day(s))" }
        else {
            # A short Security log cannot prove NTLMv1 is unused; the log size finding below says why
            $coveredHours = '?'
            if ($f.SecurityOldest -is [datetime]) { $coveredHours = [math]::Round(($Now - $f.SecurityOldest).TotalHours, 0) }
            Write-Status INFO "$tag no NTLMv1 logons found, but the Security log only covers $coveredHours hour(s) - too short to rule NTLMv1 out"
        }
        if (-not $f.AuditNtlmInDomain -and -not $f.AuditReceivingNtlm) { Write-Status INFO "$tag NTLM auditing is off. Turn it on to learn what still uses NTLM before Microsoft disables it by default" }
        if ($null -ne $f.BlockNtlmv1SSO -and [int]$f.BlockNtlmv1SSO -eq 0) { Write-Status WARN "$tag BlockNtlmv1SSO is set to 0 (NTLMv1 single sign-on explicitly allowed) - Microsoft treats this as a temporary exception" }

        # SMB
        if ($null -eq $f.Smb1Enabled) { Write-Status INFO "$tag could not read the SMB server settings" }
        elseif ($f.Smb1Enabled -eq $true) { Write-Status FAIL "$tag SMBv1 is enabled" }
        elseif ("$($f.Smb1Feature)" -eq 'Installed') { Write-Status WARN "$tag SMBv1 is disabled but the FS-SMB1 feature is still installed - remove it" }
        else { Write-Status PASS "$tag SMBv1 is off" }
        if ($f.SmbRequireSigning -eq $false) { Write-Status FAIL "$tag SMB signing is not required (the Default Domain Controllers Policy normally requires it)" }
        elseif ($f.SmbRequireSigning -eq $true) { Write-Status PASS "$tag SMB signing is required" }

        # Print Spooler
        if ("$($f.SpoolerStatus)" -eq 'Running') {
            if ([int]$f.SharedPrinters -gt 0) { Write-Status WARN "$tag Print Spooler is running and shares $($f.SharedPrinters) printer(s) - move printing off the DC" }
            else { Write-Status WARN "$tag Print Spooler is running with no shared printers - stop and disable it (it is a known way to force a DC to authenticate to an attacker)" }
        } elseif ($f.SpoolerStatus) { Write-Status PASS "$tag Print Spooler is $($f.SpoolerStatus) ($($f.SpoolerStart))" }

        # Audit policy
        $auditPolicy = @($f.AuditPolicy | Where-Object { $_ })
        if ($auditPolicy.Count -eq 0) { Write-Status INFO "$tag could not read the audit policy (auditpol)" }
        elseif (-not ($auditPolicy | Where-Object { "$($_.Setting)" -match 'Success|Failure|No Auditing' })) { Write-Status INFO "$tag audit policy output is not in English - review it by hand" }
        else {
            $auditGaps = @()
            foreach ($want in $AuditExpected) {
                $auditRow = $auditPolicy | Where-Object { $_.Guid -eq $want.Guid } | Select-Object -First 1
                if (-not $auditRow) { $auditRow = $auditPolicy | Where-Object { $_.Name -eq $want.Name } | Select-Object -First 1 }
                $have = 'not found'
                if ($auditRow) { $have = "$($auditRow.Setting)" }
                $covered = $true
                if ($want.Need -match 'Success' -and $have -notmatch 'Success') { $covered = $false }
                if ($want.Need -match 'Failure' -and $have -notmatch 'Failure') { $covered = $false }
                if (-not $covered) { $auditGaps += "$($want.Name) (now '$have', want '$($want.Need)')" }
            }
            if ($auditGaps.Count -eq 0) { Write-Status PASS "$tag audit policy records the expected account, logon and directory-change events" }
            else { Write-Status WARN "$tag audit policy gaps - $($auditGaps -join '; ')" }
        }

        # Security log size and history
        if ($f.SecurityOldest) {
            $logHours = ($Now - $f.SecurityOldest).TotalHours
            $logMsg = "$tag Security log holds $([math]::Round($logHours, 0)) hours of history (maximum size $($f.SecurityLogMaxMB) MB)"
            if ($logHours -lt 24) { Write-Status FAIL "$logMsg - too short to investigate anything. Raise the size and/or forward the log to a SIEM" }
            elseif ($logHours -lt 168) { Write-Status WARN "$logMsg - under 7 days" }
            else { Write-Status PASS $logMsg }
        }
        foreach ($clearedAt in @($f.LogCleared)) {
            if ($clearedAt) { Write-Status WARN "$tag the Security log was cleared on $($clearedAt.ToString('yyyy-MM-dd HH:mm')) (event 1102) - confirm who did it and why" }
        }

        # Leftover exceptions
        if ($null -ne $f.DsrmAdminLogonBehavior -and [int]$f.DsrmAdminLogonBehavior -eq 2) { Write-Status FAIL "$tag DsrmAdminLogonBehavior is 2 - the DSRM administrator can log on over the network at any time (a known persistence trick)" }
        if ($f.NetlogonAllowList) { Write-Status FAIL "$tag a Netlogon vulnerable-channel allow list is configured (Zerologon exception) - remove it" }
        } catch { Write-Status WARN "$tag hardening checks stopped early - $($_.Exception.Message)" }
    }
} catch { Write-Status FAIL "Section error: $($_.Exception.Message)" }

# ---------------------------------------------------------------------------------------------
Write-Section '18. KERBEROS ENCRYPTION (RC4 RETIREMENT)'
try {
    $rc4Date = Format-Date $Baseline.Rc4EnforcementDate
    Write-Status INFO "DCs patched since $rc4Date no longer issue RC4 tickets by default (KB5073381), and the rollback setting was removed in July 2026. Anything that still needs RC4 has to be fixed per account."
    $refusedIds = 203, 204, 208, 209
    foreach ($dc in $DCs) {
        $f = $DCFacts[$dc.Name]
        $tag = $dc.Name + ':'
        if (-not $f) { Write-Status WARN "$tag no data collected"; continue }
        try {
        if ($f.LastPatch -and $f.LastPatch -lt $Baseline.Rc4EnforcementDate) { Write-Status WARN "$tag not updated since before $rc4Date, so it still uses the old RC4 default. Behaviour changes the day it is patched" }

        $domainEncTypes = $f.KdcDefaultEncTypes
        if ($null -eq $domainEncTypes) { Write-Status PASS "$tag DefaultDomainSupportedEncTypes is not set (the AES-only default applies)" }
        else {
            $encHex = '0x{0:X}' -f [int]$domainEncTypes
            if (([int]$domainEncTypes -band 7) -ne 0) { Write-Status FAIL "$tag DefaultDomainSupportedEncTypes is $encHex and still allows RC4 or DES for accounts without their own setting" }
            else { Write-Status PASS "$tag DefaultDomainSupportedEncTypes is $encHex (AES only)" }
        }
        if ($null -ne $f.Rc4Phase) { Write-Status INFO "$tag RC4DefaultDisablementPhase is still set to $($f.Rc4Phase). Windows ignores it since July 2026, so it can be removed" }

        $kdcEvents = @($f.KdcRc4Events | Where-Object { $_ })
        if ($kdcEvents.Count -eq 0) { Write-Status PASS "$tag no KDC RC4 audit events (System log 201-209) in the last 30 days" }
        foreach ($kdcEvent in $kdcEvents) {
            $kdcMsg = "$tag KDC event $($kdcEvent.Id) x$($kdcEvent.Count), last on $($kdcEvent.LastSeen.ToString('yyyy-MM-dd HH:mm')) - $(Limit-Text $kdcEvent.Sample 220)"
            if ($refusedIds -contains [int]$kdcEvent.Id) { Write-Status FAIL "$kdcMsg  (a ticket was refused because RC4 is no longer allowed)" }
            elseif ([int]$kdcEvent.Id -eq 205) { Write-Status FAIL "$kdcMsg  (DefaultDomainSupportedEncTypes allows an insecure cipher)" }
            else { Write-Status WARN "$kdcMsg  (something still depends on RC4)" }
        }
        } catch { Write-Status WARN "$tag Kerberos checks stopped early - $($_.Exception.Message)" }
    }

    Write-Sub 'Accounts limited to old ciphers'
    try {
    $encAccounts = @(@($AllUsers) + @($AllComputers) | Where-Object { $_.Enabled -and $null -ne $_.'msDS-SupportedEncryptionTypes' -and [int]$_.'msDS-SupportedEncryptionTypes' -ne 0 })
    $noAes = @($encAccounts | Where-Object { ([int]$_.'msDS-SupportedEncryptionTypes' -band 24) -eq 0 -and ([int]$_.'msDS-SupportedEncryptionTypes' -band 7) -ne 0 })
    if ($noAes.Count -gt 0) {
        Show-Table ($noAes | ForEach-Object { [pscustomobject]@{ Account = $_.SamAccountName; Type = $_.ObjectClass; EncTypes = ('0x{0:X}' -f [int]$_.'msDS-SupportedEncryptionTypes'); PasswordSet = Format-Date $_.PasswordLastSet } }) -Flag { param($row) 'FAIL' }
        Write-Status FAIL "$($noAes.Count) enabled account(s) are set to RC4 or DES only, with no AES - $(Limit-Text (($noAes | ForEach-Object { $_.SamAccountName }) -join ', ') 400)"
    } else { Write-Status PASS 'No enabled account is restricted to RC4 or DES' }
    $rc4Exceptions = @($AllUsers | Where-Object { $_.Enabled -and $null -ne $_.'msDS-SupportedEncryptionTypes' -and ([int]$_.'msDS-SupportedEncryptionTypes' -band 4) -ne 0 -and ([int]$_.'msDS-SupportedEncryptionTypes' -band 24) -ne 0 })
    if ($rc4Exceptions.Count -gt 0) { Write-Status INFO "User accounts that explicitly allow RC4 as well as AES (deliberate exceptions?) - $(Limit-Text (($rc4Exceptions | ForEach-Object { $_.SamAccountName }) -join ', ') 300)" }
    } catch { Write-Status WARN "The account cipher check could not finish - $($_.Exception.Message)" }

    Write-Sub 'Service accounts that may have no AES keys'
    $aesSince = $null
    try { $aesSince = (Get-ADGroup -Identity "$DomSID-521" -Properties whenCreated -Server $PDC).whenCreated } catch { }
    if (-not $aesSince) {
        Write-Status INFO 'Could not work out when this domain first supported AES (Read-only Domain Controllers group not found)'
    } else {
        # A password last set before the domain supported AES has no AES keys (a widely used rule of thumb, not a Microsoft test)
        $oldServiceAccounts = @($AllUsers | Where-Object { $_.Enabled -and $_.SamAccountName -ne 'krbtgt' -and $_.servicePrincipalName -and $_.PasswordLastSet -and $_.PasswordLastSet -lt $aesSince })
        if ($oldServiceAccounts.Count -gt 0) { Write-Status WARN "$($oldServiceAccounts.Count) service account(s) have a password older than AES support in this domain ($(Format-Date $aesSince)) and probably have no AES keys. Tickets for them now fail until the password is reset - $(Limit-Text (($oldServiceAccounts | ForEach-Object { $_.SamAccountName }) -join ', ') 300)" }
        else { Write-Status PASS "Every service account password was set after this domain gained AES support ($(Format-Date $aesSince))" }
        $oldUserPasswords = @($AllUsers | Where-Object { $_.Enabled -and -not $_.servicePrincipalName -and $_.PasswordLastSet -and $_.PasswordLastSet -lt $aesSince })
        if ($oldUserPasswords.Count -gt 0) { Write-Status INFO "$($oldUserPasswords.Count) other enabled account(s) also have a password that predates AES support - $(Limit-Text (($oldUserPasswords | ForEach-Object { $_.SamAccountName }) -join ', ') 300)" }
    }
} catch { Write-Status FAIL "Section error: $($_.Exception.Message)" }

# ---------------------------------------------------------------------------------------------
Write-Section '19. DIRECTORY PERMISSIONS AND DELEGATION'
try {
    # --- Replication (DCSync) rights: whoever holds both rights can read every password hash in the domain
    Write-Sub 'Replication (DCSync) rights on the domain'
    try {
    $replicationRights = @{
        '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'Get-Changes'
        '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'Get-Changes-All'
        '89e95b76-444d-4c62-991a-0facbeda640c' = 'Get-Changes-In-Filtered-Set'
    }
    $rootAcl = Get-AdAcl -DN $DomDN -Server $PDC
    $replicationHolders = @{}
    foreach ($rule in $rootAcl.Rules) {
        if ("$($rule.AccessControlType)" -ne 'Allow') { continue }
        if ("$($rule.InheritanceType)" -eq 'Descendents' -or "$($rule.InheritanceType)" -eq 'Children') { continue }
        $ruleRights = [int]$rule.ActiveDirectoryRights
        $granted = @()
        if (($ruleRights -band $ADR.GenericAll) -eq $ADR.GenericAll) { $granted = @('Get-Changes', 'Get-Changes-All') }
        elseif (($ruleRights -band $ADR.ExtendedRight) -ne 0) {
            $rightGuid = "$($rule.ObjectType)".ToLower()
            if ($rule.ObjectType -eq $EmptyGuid) { $granted = @('Get-Changes', 'Get-Changes-All') }
            elseif ($replicationRights.ContainsKey($rightGuid)) { $granted = @($replicationRights[$rightGuid]) }
        }
        if ($granted.Count -eq 0) { continue }
        $holderSid = "$($rule.IdentityReference.Value)"
        if (-not $replicationHolders.ContainsKey($holderSid)) { $replicationHolders[$holderSid] = New-Object System.Collections.Generic.List[string] }
        foreach ($right in $granted) { if (-not $replicationHolders[$holderSid].Contains($right)) { $replicationHolders[$holderSid].Add($right) } }
    }
    $defaultHolders = @('S-1-5-32-544', 'S-1-5-9', 'S-1-5-18', "$DomSID-516", "$DomSID-512", "$RootSID-519", "$RootSID-498")
    $syncBySid = @{}
    foreach ($syncAccount in $SyncServers) { if ($syncAccount.Sid) { $syncBySid[$syncAccount.Sid] = $syncAccount } }
    $cloudSyncSids = @($CloudSyncGmsa | ForEach-Object { "$($_.SID)" })
    $replicationRows = @()
    foreach ($holderSid in @($replicationHolders.Keys)) {
        $holderName = Resolve-SidName $holderSid
        $holderRights = $replicationHolders[$holderSid] -join ', '
        $canReadHashes = $replicationHolders[$holderSid].Contains('Get-Changes-All')
        $verdict = 'Default'
        $severity = ''
        if ($defaultHolders -contains $holderSid) { $verdict = 'Default' }
        elseif ($syncBySid.ContainsKey($holderSid)) {
            $syncAccount = $syncBySid[$holderSid]
            $syncHostAlive = [bool]($AllComputers | Where-Object { $_.Name -ieq $syncAccount.Server -and $_.Enabled })
            if ($syncHostAlive) { $verdict = "Entra Connect on $($syncAccount.Server) (expected)" }
            elseif ($syncAccount.Enabled) { $verdict = 'Entra Connect account whose server is gone'; $severity = 'FAIL' }
            else { $verdict = 'Disabled Entra Connect account whose server is gone'; $severity = 'WARN' }
        }
        elseif ($cloudSyncSids -contains $holderSid) { $verdict = 'Entra Cloud Sync agent (expected)' }
        elseif ($script:AdminSids.Contains($holderSid)) { $verdict = 'Already an administrator' }
        elseif ($canReadHashes) { $verdict = 'NOT a default - can read every password hash'; $severity = 'FAIL' }
        else { $verdict = 'Not a default (partial right)'; $severity = 'WARN' }
        $replicationRows += [pscustomobject]@{ Principal = $holderName; Rights = $holderRights; Verdict = $verdict; Severity = $severity; Hint = (Get-ReplicationHint $holderName $verdict) }
    }
    Show-Table ($replicationRows | Sort-Object Principal | Select-Object -Property 'Principal', 'Rights', 'Verdict') -Flag {
        param($row)
        # -cmatch: 'NOT a default' (FAIL) and 'Not a default' (WARN) differ only by case
        if ("$($row.Verdict)" -cmatch 'NOT a default|server is gone') { 'FAIL' } elseif ("$($row.Verdict)" -cmatch 'Not a default') { 'WARN' }
    }
    $replicationIssues = @($replicationRows | Where-Object { $_.Severity })
    foreach ($issue in $replicationIssues) {
        Write-Status $issue.Severity "DCSync rights - '$($issue.Principal)' holds $($issue.Rights) on the domain ($($issue.Verdict)). $($issue.Hint)"
    }
    if ($replicationIssues.Count -eq 0) { Write-Status PASS 'Only default principals and current sync accounts hold replication (DCSync) rights' }
    } catch { Write-Status WARN "The DCSync rights check could not finish - $($_.Exception.Message)" }

    # --- Control of the objects that control the domain
    Write-Sub 'High-impact permissions on key objects'
    try {
    $aclFindings = 0
    $aclFindings += Test-AclTarget -DN $DomDN -Label 'Domain root' -CheckOwner
    $aclFindings += Test-AclTarget -DN "CN=AdminSDHolder,CN=System,$DomDN" -Label 'AdminSDHolder' -CheckOwner
    $aclFindings += Test-AclTarget -DN "$($Domain.DomainControllersContainer)" -Label 'Domain Controllers OU' -CheckOwner
    foreach ($dc in $DCs) {
        if ($dc.ComputerObjectDN) { $aclFindings += Test-AclTarget -DN "$($dc.ComputerObjectDN)" -Label "DC computer object $($dc.Name)" -CheckOwner }
    }
    if ($aclFindings -eq 0) { Write-Status PASS 'No non-admin principal has full control, permission-change, ownership or write-all rights on the domain root, AdminSDHolder, the Domain Controllers OU or the DC objects' }

    $gpoObjects = @(Get-ADObject -SearchBase "CN=Policies,CN=System,$DomDN" -LDAPFilter '(objectClass=groupPolicyContainer)' -Properties 'displayName' -Server $PDC)
    $gpoAclFindings = 0
    foreach ($gpoObject in $gpoObjects) {
        $gpoAclFindings += Test-AclTarget -DN "$($gpoObject.DistinguishedName)" -Label "GPO '$($gpoObject.displayName)'" -CheckOwner
    }
    if ($gpoAclFindings -eq 0) { Write-Status PASS "No non-admin principal can edit or take over any of the $($gpoObjects.Count) GPOs" }
    } catch { Write-Status WARN "The permissions check could not finish - $($_.Exception.Message)" }

    # --- Directory-wide switches
    Write-Sub 'Directory-wide settings'
    try {
    $directoryService = Get-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,$ConfigNC" -Properties 'dSHeuristics' -Server $PDC
    $heuristics = "$($directoryService.dSHeuristics)"
    $heuristicIssues = 0
    if ($heuristics.Length -ge 7 -and $heuristics.Substring(6, 1) -eq '2') { $heuristicIssues++; Write-Status FAIL 'Anonymous LDAP access is enabled forest-wide (dSHeuristics character 7 is 2)' }
    if ($heuristics.Length -ge 16 -and $heuristics.Substring(15, 1) -ne '0') { $heuristicIssues++; Write-Status FAIL 'dSHeuristics removes one or more operator groups from AdminSDHolder protection (character 16 is not 0)' }
    if ($heuristicIssues -eq 0) { Write-Status PASS "dSHeuristics has no risky overrides (value: $(if ($heuristics) { $heuristics } else { 'not set' }))" }

    $preWin2000 = Get-ADGroup -Identity 'S-1-5-32-554' -Properties 'member' -Server $PDC
    $preWinOther = @()
    $preWinOpen = @()
    $preWinAuthUsers = $false
    foreach ($memberDN in @($preWin2000.member)) {
        if (-not $memberDN) { continue }
        $memberCn = Get-CnFromDN $memberDN
        if ($memberCn -eq 'S-1-1-0') { $preWinOpen += 'Everyone' }
        elseif ($memberCn -eq 'S-1-5-7') { $preWinOpen += 'Anonymous Logon' }
        elseif ($memberCn -eq 'S-1-5-11') { $preWinAuthUsers = $true }
        elseif ($memberCn -match '^S-1-') { $preWinOther += (Resolve-SidName $memberCn) }
        else { $preWinOther += $memberCn }
    }
    if ($preWinOpen.Count -gt 0) { Write-Status FAIL "Pre-Windows 2000 Compatible Access contains $($preWinOpen -join ' and ') - unauthenticated users can list accounts and groups" }
    if ($preWinOther.Count -gt 0) { Write-Status WARN "Pre-Windows 2000 Compatible Access has extra members - $($preWinOther -join ', ')" }
    if ($preWinAuthUsers) { Write-Status INFO 'Pre-Windows 2000 Compatible Access contains Authenticated Users (the common default). Removing it is more secure but can break old applications and NAS devices' }
    if ($preWinOpen.Count -eq 0 -and $preWinOther.Count -eq 0) { Write-Status PASS 'Pre-Windows 2000 Compatible Access has no anonymous or unexpected members' }
    } catch { Write-Status WARN "The directory settings check could not finish - $($_.Exception.Message)" }

    # --- Kerberos delegation that reaches DCs or key accounts
    Write-Sub 'Kerberos delegation'
    try {
    $rbcdTargets = @()
    try { $rbcdTargets += @(Get-ADComputer -LDAPFilter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' -Properties 'PrincipalsAllowedToDelegateToAccount' -Server $PDC) } catch { }
    try { $rbcdTargets += @(Get-ADUser -LDAPFilter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' -Properties 'PrincipalsAllowedToDelegateToAccount' -Server $PDC) } catch { }
    foreach ($rbcdTarget in $rbcdTargets) {
        $allowed = (@($rbcdTarget.PrincipalsAllowedToDelegateToAccount) | Where-Object { $_ } | ForEach-Object { Get-CnFromDN $_ }) -join ', '
        if ($DCNameSet.Contains("$($rbcdTarget.Name)") -or "$($rbcdTarget.SamAccountName)" -eq 'krbtgt') {
            Write-Status FAIL "Resource-based delegation on $($rbcdTarget.Name) - '$allowed' can impersonate any user to it, which is a path to domain takeover"
        } else {
            Write-Status WARN "Resource-based delegation on $($rbcdTarget.Name) - '$allowed' can impersonate any user to it. Confirm it is intended"
        }
    }
    if ($rbcdTargets.Count -eq 0) { Write-Status PASS 'No resource-based constrained delegation is configured' }

    $dcNamePattern = ($DCs | ForEach-Object { [regex]::Escape($_.Name) }) -join '|'
    $toDcPattern = '^[^/]+/(' + $dcNamePattern + ')(\.|:|/|$)'
    $delegationIssues = 0
    foreach ($delegator in @(@($AllUsers) + @($AllComputers) | Where-Object { $_.'msDS-AllowedToDelegateTo' })) {
        $delegationTargets = @($delegator.'msDS-AllowedToDelegateTo' | ForEach-Object { "$_" })
        $toKeyAccounts = @($delegationTargets | Where-Object { $_ -match 'krbtgt|AZUREADSSOACC' })
        $toDcLdap = @($delegationTargets | Where-Object { $_ -match $toDcPattern -and $_ -match '^ldap/' })
        $toDcOther = @($delegationTargets | Where-Object { $_ -match $toDcPattern -and $_ -notmatch '^ldap/' })
        if ($toKeyAccounts.Count -gt 0) { $delegationIssues++; Write-Status FAIL "$($delegator.SamAccountName) may delegate to $($toKeyAccounts -join ', ') - it can forge tickets for any user" }
        if ($toDcLdap.Count -gt 0) { $delegationIssues++; Write-Status FAIL "$($delegator.SamAccountName) may delegate to LDAP on a domain controller ($($toDcLdap -join ', ')) - equivalent to DCSync" }
        if ($toDcOther.Count -gt 0) { $delegationIssues++; Write-Status WARN "$($delegator.SamAccountName) may delegate to a service on a domain controller ($($toDcOther -join ', '))" }
    }
    if ($delegationIssues -eq 0) { Write-Status PASS 'No constrained delegation points at krbtgt, the Seamless SSO account or a domain controller' }

    $seamlessSso = $AllComputers | Where-Object { $_.Name -eq 'AZUREADSSOACC' } | Select-Object -First 1
    if ($seamlessSso) {
        $ssoKeyAge = Get-AgeDays $seamlessSso.PasswordLastSet
        if ($null -eq $ssoKeyAge -or $ssoKeyAge -gt 30) { Write-Status WARN "Entra Seamless SSO account AZUREADSSOACC has a Kerberos key that is $ssoKeyAge days old. Microsoft recommends rolling it at least every 30 days" }
        else { Write-Status PASS "Entra Seamless SSO key was rolled $ssoKeyAge days ago" }
    }
    } catch { Write-Status WARN "The delegation check could not finish - $($_.Exception.Message)" }

    # --- SID history and trusts
    Write-Sub 'SID history and trusts'
    try {
    $sidHistoryObjects = @(Get-ADObject -LDAPFilter '(sIDHistory=*)' -Properties 'sIDHistory', 'sAMAccountName' -Server $PDC)
    foreach ($historyObject in $sidHistoryObjects) {
        $historySids = @($historyObject.sIDHistory | ForEach-Object { "$_" })
        $dangerousHistory = @($historySids | Where-Object { $_ -like "$DomSID-*" -or $_ -match '-(500|512|518|519|544)$' })
        if ($dangerousHistory.Count -gt 0) { Write-Status FAIL "$($historyObject.sAMAccountName) carries SID history that grants hidden admin or same-domain rights ($($dangerousHistory -join ', '))" }
        else { Write-Status WARN "$($historyObject.sAMAccountName) still has SID history from a migration ($($historySids.Count) value(s)) - remove it once the migration is finished" }
    }
    if ($sidHistoryObjects.Count -eq 0) { Write-Status PASS 'No account has SID history' }

    $trusts = @(Get-ADTrust -Filter * -Properties 'whenChanged', 'trustAttributes' -Server $PDC)
    if ($trusts.Count -eq 0) {
        Write-Status INFO 'No domain or forest trusts'
    } else {
        Show-Table ($trusts | ForEach-Object {
                [pscustomobject]@{
                    Trust           = $_.Name
                    Direction       = "$($_.Direction)"
                    Forest          = $_.ForestTransitive
                    WithinForest    = $_.IntraForest
                    SidFiltering    = $_.SIDFilteringQuarantined
                    SelectiveAuth   = $_.SelectiveAuthentication
                    TgtDelegation   = Test-TgtDelegation $_.TrustAttributes
                    LastChangedDays = Get-AgeDays $_.whenChanged
                }
            }) -Flag { param($row) if ($row.TgtDelegation -or ($null -ne $row.LastChangedDays -and $row.LastChangedDays -gt 60)) { 'WARN' } }
        foreach ($trust in $trusts) {
            $trustAge = Get-AgeDays $trust.whenChanged
            if (-not $trust.IntraForest -and -not $trust.ForestTransitive -and -not $trust.SIDFilteringQuarantined) { Write-Status FAIL "Trust with $($trust.Name) is an external trust with SID filtering turned off - the other domain can claim admin rights here" }
            if (Test-TgtDelegation $trust.TrustAttributes) { Write-Status WARN "Trust with $($trust.Name) allows TGT delegation across the trust (trustAttributes 0x800 set)" }
            if ($null -ne $trustAge -and $trustAge -gt 60) { Write-Status WARN "Trust with $($trust.Name) has not changed in $trustAge days. Trust passwords rotate about every 30 days, so it may be dead" }
        }
    }
    } catch { Write-Status WARN "The SID history and trust check could not finish - $($_.Exception.Message)" }
} catch { Write-Status FAIL "Section error: $($_.Exception.Message)" }

# ---------------------------------------------------------------------------------------------
Write-Section "20. MEMBER SERVERS ($($MemberServers.Count) enabled Windows Server computer objects, DCs excluded)"
try {
    if ($SkipMemberServers) {
        Write-Status INFO 'Member server collection was skipped (-SkipMemberServers)'
    } elseif ($MemberServers.Count -eq 0) {
        Write-Status INFO 'No member servers found in AD'
    } else {
        $serverRows = foreach ($srv in $MemberServers) {
            $key = Get-ShortName $srv.Name
            $facts = $SrvFacts[$key]
            $tightest = ''
            if ($facts) {
                $lowDisk = @($facts.Disks | Where-Object { $_ }) | Sort-Object FreePct | Select-Object -First 1
                if ($lowDisk) { $tightest = "$($lowDisk.Drive) $($lowDisk.FreePct)% free" }
            }
            [pscustomobject]@{
                Server       = $srv.Name
                OS           = ("$($srv.OperatingSystem)" -replace 'Windows Server ', '')
                State        = "$($SrvState[$key])"
                UptimeDays   = $(if ($facts) { Get-AgeDays $facts.LastBoot } else { '' })
                LastPatch    = $(if ($facts -and $facts.LastPatch -is [datetime]) { Format-Date $facts.LastPatch } elseif ($facts) { 'unknown' } else { '' })
                RebootNeeded = $(if ($facts) { $facts.PendingReboot } else { '' })
                'RAM%'       = $(if ($facts) { $facts.RamUsedPct } else { '' })
                'CPU%'       = $(if ($facts) { $facts.CpuLoadPct } else { '' })
                TightestDisk = $tightest
                LastLogonAD  = Format-Date $srv.LastLogonDate
            }
        }
        Show-Table $serverRows -Flag {
            param($row)
            if ("$($row.State)" -eq 'Offline' -or "$($row.State)" -like 'Error*' -or "$($row.State)" -like 'No answer*') { 'WARN' }
            elseif ("$($row.TightestDisk)" -match ' (\d+(\.\d+)?)% free') { if ([double]$Matches[1] -lt 10) { 'FAIL' } elseif ([double]$Matches[1] -lt 20) { 'WARN' } }
        }

        $diskRows = @()
        $eventRows = @()
        foreach ($srv in $MemberServers) {
            $key = Get-ShortName $srv.Name
            $tag = $srv.Name + ':'
            $state = "$($SrvState[$key])"
            $facts = $SrvFacts[$key]
            try {
            if (-not $facts) {
                if ($state -eq 'Stale in AD') { Write-Status INFO "$tag not contacted - no domain logon in $StaleDays+ days (listed under stale computers in section 12)" }
                elseif ($state -eq 'Offline') { Write-Status WARN "$tag does not answer ping or WinRM, yet it logged on to the domain on $(Format-Date $srv.LastLogonDate). Confirm it is running" }
                elseif ($state -eq 'WinRM not reachable') { Write-Status INFO "$tag answers ping but WinRM (TCP 5985) is closed, so nothing could be collected" }
                else { Write-Status WARN "$tag could not collect data - $(Limit-Text $state 200)" }
                continue
            }

            foreach ($disk in @($facts.Disks | Where-Object { $_ })) {
                $diskRows += [pscustomobject]@{ Server = $srv.Name; Drive = $disk.Drive; Label = $disk.Label; SizeGB = $disk.SizeGB; FreeGB = $disk.FreeGB; 'Free%' = $disk.FreePct }
                $diskMsg = "$tag drive $($disk.Drive) $($disk.FreeGB) GB free of $($disk.SizeGB) GB ($($disk.FreePct)%)"
                if ($disk.FreePct -lt 10) { Write-Status FAIL $diskMsg } elseif ($disk.FreePct -lt 20) { Write-Status WARN $diskMsg }
            }
            $serverUptime = Get-AgeDays $facts.LastBoot
            $serverPatchAge = Get-AgeDays $facts.LastPatch
            if ($null -ne $serverUptime -and $serverUptime -gt $Baseline.MaxDcUptimeDays) { Write-Status WARN "$tag uptime $serverUptime days (last boot $(Format-Date $facts.LastBoot))" }
            if ($null -eq $serverPatchAge) { Write-Status WARN "$tag could not determine the last patch date (Get-HotFix returned no install dates) - check Windows Update history on the server" }
            elseif ($serverPatchAge -gt $Baseline.MaxPatchAgeDays) { Write-Status WARN "$tag last update installed $serverPatchAge days ago ($($facts.LastPatchKB) on $(Format-Date $facts.LastPatch))" }
            if ($facts.PendingReboot) { Write-Status WARN "$tag reboot pending" }
            if ($null -ne $facts.RamUsedPct -and $facts.RamUsedPct -ge 95) { Write-Status WARN "$tag memory $($facts.RamUsedPct)% used of $($facts.RamTotalGB) GB" }

            $noisyEvents = @($facts.Events | Where-Object { $_ -and $_.Count -ge 20 })
            foreach ($serverEvent in @($facts.Events | Where-Object { $_ -and $_.Count -ge 3 } | Select-Object -First 4)) {
                $eventRows += [pscustomobject]@{ Server = $srv.Name; Log = $serverEvent.Log; Source = Limit-Text ("$($serverEvent.Source)" -replace '^Microsoft-Windows-', '') 28; Id = $serverEvent.Id; Count = $serverEvent.Count; LastSeen = $serverEvent.LastSeen.ToString('MM-dd HH:mm'); Message = Limit-Text $serverEvent.Message 70 }
            }
            if ($noisyEvents.Count -gt 0) {
                $eventSummary = ($noisyEvents | Select-Object -First 3 | ForEach-Object {
                        $shortSource = "$($_.Source)" -replace '^Microsoft-Windows-', ''
                        "$shortSource $($_.Id) x$($_.Count)"
                    }) -join '; '
                Write-Status WARN "$tag recurring errors in the last $EventDays days - $eventSummary"
                $script:TopRecurring += "$($srv.Name): $eventSummary"
            }
            $stoppedServices = @($facts.StoppedAuto | Where-Object { $_ })
            if ($stoppedServices.Count -gt 0) { Write-Status INFO "$tag automatic services not running - $(Limit-Text ($stoppedServices -join ', ') 250)" }
            } catch { Write-Status WARN "$tag results could not be processed - $($_.Exception.Message)" }
        }

        if ($diskRows.Count -gt 0) {
            Write-Sub 'Disk space on member servers'
            Show-Table $diskRows -Flag { param($row) if ($row.'Free%' -lt 10) { 'FAIL' } elseif ($row.'Free%' -lt 20) { 'WARN' } }
        }
        if ($eventRows.Count -gt 0) {
            Write-Sub "Most frequent error events per member server (last $EventDays days)"
            Show-Table $eventRows -Flag { param($row) if ($row.Count -ge 20) { 'WARN' } }
        }
        $collectedCount = @($MemberServers | Where-Object { $SrvFacts[(Get-ShortName $_.Name)] }).Count
        Write-Status INFO "Collected data from $collectedCount of $($MemberServers.Count) member server(s)"
    }
} catch { Write-Status FAIL "Section error: $($_.Exception.Message)" }

# ---------------------------------------------------------------------------------------------
Write-Section "21. RECURRING EVENT LOG ISSUES ON DCs (last $EventDays days)"
$NotableEvents = @{
    'Directory Service|1311' = 'KCC cannot build a complete replication topology'
    'Directory Service|1655' = 'Could not reach a global catalog'
    'Directory Service|1864' = 'DC has not replicated with partners within the threshold'
    'Directory Service|1925' = 'Replication link could not be established'
    'Directory Service|1988' = 'Lingering object detected'
    'Directory Service|2042' = 'Replication blocked - exceeded tombstone lifetime'
    'Directory Service|2087' = 'DNS lookup failure blocked replication'
    'Directory Service|2088' = 'DNS lookup failure (replication fell back to NetBIOS)'
    'Directory Service|2089' = 'A directory partition has not been backed up within the backup latency window'
    'DFS Replication|2213'   = 'DFSR paused after unexpected shutdown'
    'DFS Replication|4012'   = 'SYSVOL replication stopped (MaxOfflineTimeInDays exceeded)'
    'DFS Replication|5002'   = 'DFSR cannot communicate with partner'
    'DFS Replication|5008'   = 'DFSR cannot communicate with partner'
    'DFS Replication|5014'   = 'DFSR connection to partner interrupted'
    'DNS Server|4000'        = 'DNS server cannot open AD DS'
    'DNS Server|4013'        = 'DNS waiting for AD DS initial synchronization'
    'DNS Server|4015'        = 'DNS server cannot read from AD DS'
    'Microsoft-Windows-Time-Service|36'  = 'Time service has not synchronized recently'
    'Microsoft-Windows-Time-Service|47'  = 'No valid response from manually configured NTP peer'
    'Microsoft-Windows-Time-Service|129' = 'NTP client cannot reach its time source'
    'Microsoft-Windows-Time-Service|134' = 'NTP client cannot resolve its time source'
    'Microsoft-Windows-Time-Service|142' = 'Time service stopped advertising as a time source'
    'NETLOGON|5719' = 'Cannot set up a secure session with a DC'
    'NETLOGON|5722' = 'Computer account authentication failed (broken secure channel)'
    'NETLOGON|5723' = 'No trust account for a computer (broken secure channel)'
    'NETLOGON|5774' = 'DC locator DNS record registration failed'
    'NETLOGON|5781' = 'Dynamic registration of DC DNS records failed'
    'NETLOGON|5807' = 'Clients connecting from IPs not mapped to any AD subnet'
    'NETLOGON|5827' = 'Vulnerable Netlogon secure channel denied (CVE-2020-1472)'
    'NETLOGON|5828' = 'Vulnerable Netlogon secure channel denied (CVE-2020-1472)'
    'NETLOGON|5829' = 'Vulnerable Netlogon secure channel ALLOWED (CVE-2020-1472)'
    'Microsoft-Windows-Kerberos-Key-Distribution-Center|14' = 'KDC encryption type problem (RC4/AES keys)'
    'Microsoft-Windows-Kerberos-Key-Distribution-Center|16' = 'KDC encryption type mismatch'
    'Microsoft-Windows-Kerberos-Key-Distribution-Center|26' = 'KDC encryption type mismatch'
    'ESENT|467' = 'Database corruption detected in an ESE database (on a DC this can be NTDS.dit)'
    'ESENT|474' = 'Database page checksum mismatch (failing disk or storage path)'
    'disk|7'    = 'Bad block on a disk'
    'disk|51'   = 'Error during a paging operation (storage path problem)'
    'disk|153'  = 'Disk I/O was retried (storage latency or path problem)'
    'Ntfs|55'   = 'File system corruption detected'
    'Microsoft-Windows-Ntfs|55' = 'File system corruption detected'
    'volsnap|25' = 'Shadow copies were deleted (backups can fail)'
    'Microsoft-Windows-Kernel-Power|41' = 'Unexpected shutdown or power loss'
    'EventLog|6008' = 'Previous shutdown was unexpected'
    'Service Control Manager|7031' = 'A service terminated unexpectedly'
    'Service Control Manager|7034' = 'A service terminated unexpectedly'
    'Microsoft-Windows-WindowsUpdateClient|20' = 'A Windows update failed to install'
}
# LDAP signing events (2886/2887) and KDC RC4 events are reported in sections 17 and 18, not here
$CriticalNotable = 'Directory Service|2042', 'Directory Service|1988', 'DFS Replication|4012', 'DFS Replication|2213', 'NETLOGON|5829', 'ESENT|467', 'ESENT|474', 'Ntfs|55', 'Microsoft-Windows-Ntfs|55', 'disk|7'
$HandledElsewhere = 'Directory Service|2886', 'Directory Service|2887', 'Directory Service|3040', 'Directory Service|3041'
$levelMap = @{ 1 = 'Critical'; 2 = 'Error'; 3 = 'Warning' }
try {
    foreach ($dc in $DCs) {
        $f = $DCFacts[$dc.Name]
        Write-Sub $dc.Name
        if (-not $f) { Write-Status WARN "$($dc.Name): no data collected"; continue }
        Show-Table (@($f.Events) | Where-Object { $_ } | ForEach-Object {
                [pscustomobject]@{ Log = $_.Log; Source = Limit-Text ($_.Source -replace '^Microsoft-Windows-', '') 28; Id = $_.Id; Level = $levelMap[[int]$_.Level]; Count = $_.Count; LastSeen = $_.LastSeen.ToString('MM-dd HH:mm'); Message = Limit-Text $_.Message 70 }
            }) -Flag { param($row) if ("$($row.Level)" -ne 'Warning' -and $row.Count -ge 3) { 'WARN' } }
        $recurring = @()
        foreach ($e in $f.Events) {
            $key1 = "$($e.Log)|$($e.Id)"; $key2 = "$($e.Source)|$($e.Id)"
            if ($HandledElsewhere -contains $key1) { continue }
            $note = $NotableEvents[$key1]; $key = $key1
            if (-not $note) { $note = $NotableEvents[$key2]; $key = $key2 }
            if ($note) {
                $sev = $(if ($key -in $CriticalNotable) { 'FAIL' } else { 'WARN' })
                Write-Status $sev "$($dc.Name): $($e.Log) event $($e.Id) x$($e.Count) - $note"
                $script:TopRecurring += "$($dc.Name): $note (x$($e.Count))"
            } elseif ($e.Level -le 2 -and $e.Count -ge 3) {
                $recurring += "$(($e.Source -replace '^Microsoft-Windows-', '')) $($e.Id) x$($e.Count)"
            }
        }
        if ($recurring) {
            Write-Status WARN "$($dc.Name): $($recurring.Count) other error event(s) recurring 3+ times: $(Limit-Text ($recurring -join '; ') 300)"
            $script:TopRecurring += "$($dc.Name): $($recurring[0])"
        }
        if (-not $f.Events) { Write-Status PASS "$($dc.Name): no errors or warnings in the monitored logs" }
    }
} catch { Write-Status FAIL "Section error: $($_.Exception.Message)" }

# ---------------------------------------------------------------------------------------------
Write-Section '22. SUMMARY'
Write-Progress -Activity 'AD Health Check' -Completed
Write-HeaderLines
$fails = @($script:Findings | Where-Object { $_.Status -eq 'FAIL' })
$warns = @($script:Findings | Where-Object { $_.Status -eq 'WARN' })

# Scoreboard: one line per section, problem sections marked in the margin
Write-Host ''
Write-Host ('    {0,-78} {1,5} {2,5} {3,5}' -f 'Section', 'FAIL', 'WARN', 'PASS') -ForegroundColor White
Write-Host ('    ' + ('-' * 96)) -ForegroundColor DarkGray
foreach ($sectionName in $script:SectionOrder) {
    if ($sectionName -like '22.*') { continue }
    $tally = $script:Counts[$sectionName]
    $scoreLine = '{0,-78} {1,5} {2,5} {3,5}' -f (Limit-Text $sectionName 78), $tally.FAIL, $tally.WARN, $tally.PASS
    if ($tally.FAIL -gt 0) { Write-Host (' !! ' + $scoreLine) -ForegroundColor Red }
    elseif ($tally.WARN -gt 0) { Write-Host ('  ! ' + $scoreLine) -ForegroundColor Yellow }
    else { Write-Host ('    ' + $scoreLine) -ForegroundColor DarkGreen }
}
Write-Host ('    ' + ('-' * 96)) -ForegroundColor DarkGray
$passTotal = 0
foreach ($sectionName in $script:SectionOrder) { if ($sectionName -notlike '22.*') { $passTotal += [int]$script:Counts[$sectionName].PASS } }
Write-Host ('    {0,-78} {1,5} {2,5} {3,5}' -f 'TOTAL', $fails.Count, $warns.Count, $passTotal) -ForegroundColor White

# Action lists: everything that failed first, then everything to review, in report order
foreach ($grp in 'FAIL', 'WARN') {
    $items = @($script:Findings | Where-Object { $_.Status -eq $grp })
    if ($items.Count -eq 0) { continue }
    Write-Host ''
    Write-Host '  ' -NoNewline
    if ($grp -eq 'FAIL') { Write-Host " FIX NOW - $($items.Count) FAIL item(s) " -ForegroundColor White -BackgroundColor DarkRed }
    else { Write-Host " REVIEW - $($items.Count) WARN item(s) " -ForegroundColor Black -BackgroundColor Yellow }
    $groupColor = 'Yellow'
    if ($grp -eq 'FAIL') { $groupColor = 'Red' }
    foreach ($sectionName in $script:SectionOrder) {
        $sectionItems = @($items | Where-Object { $_.Section -eq $sectionName })
        if ($sectionItems.Count -eq 0) { continue }
        Write-Host "    $sectionName" -ForegroundColor $groupColor
        foreach ($item in $sectionItems) { Write-Host "      - $($item.Message)" }
    }
}
if ($fails.Count -eq 0 -and $warns.Count -eq 0) { Write-Host '  No FAIL or WARN items.' -ForegroundColor Green }

Write-Host ''
Write-Host '  --- Review items (for the client review / QBR) ---' -ForegroundColor DarkCyan
Write-Host '  1. Open tickets            : review in the PSA (not checked by this script)'
Write-Host '  2. Missed SLAs             : review in the PSA (not checked by this script)'
Write-Host "  3. Recurring tech issues   : $($fails.Count) FAIL / $($warns.Count) WARN findings above; notable recurring events:"
if ($script:TopRecurring) { foreach ($t in ($script:TopRecurring | Select-Object -First 12)) { Write-Host "        - $t" } } else { Write-Host '        - none' }
Write-Host "  4. New accounts ($NewAccountDays days)  : $script:NewUserCount user(s) created, $script:NewUserNeverLogon never logged on - list in section 10 to validate with the customer"
Write-Host "  5. Admin-level access      : $script:PrivAccountCount privileged account(s), $script:PrivIssueCount with findings - section 11 (no changes made; action with the customer)"
Write-Host ''
Write-Host ('#' * 100) -ForegroundColor White
Write-Host "  End of report - $DomDNS - $((Get-Date).ToString('yyyy-MM-dd HH:mm'))  (run time $([int]((Get-Date) - $Now).TotalSeconds) seconds)" -ForegroundColor White
Write-Host ('#' * 100) -ForegroundColor White

#endregion
