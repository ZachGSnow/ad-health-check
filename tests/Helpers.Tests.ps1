# Unit tests for the pure helper functions of Invoke-ADHealthCheck.ps1.
# The functions are loaded from the parsed script; nothing here needs a domain.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    . ([scriptblock]::Create((Get-ScriptFunctionText)))
    $script:Now = [datetime]'2026-11-14'
}

Describe 'Get-OSSupport' {
    It 'returns <Expected> for <OS> <Version> on <Today>' -ForEach @(
        @{ OS = 'Windows Server 2012 R2 Standard'; Version = '6.3 (9600)'; Today = '2026-11-14'; Expected = 'EOL' }
        @{ OS = 'Windows 10 Pro'; Version = '10.0 (19045)'; Today = '2026-11-14'; Expected = 'EOL (Oct 2025)' }
        @{ OS = 'Windows 10 Enterprise LTSC'; Version = '10.0 (19044)'; Today = '2026-11-14'; Expected = 'Check LTSC' }
        @{ OS = 'Windows Server 2016 Standard'; Version = '10.0 (14393)'; Today = '2026-06-01'; Expected = 'Supported' }
        @{ OS = 'Windows Server 2016 Standard'; Version = '10.0 (14393)'; Today = '2026-11-14'; Expected = 'EOS 2027-01-12' }
        @{ OS = 'Windows Server 2016 Standard'; Version = '10.0 (14393)'; Today = '2027-02-01'; Expected = 'EOL (2027-01)' }
        @{ OS = 'Windows 11 Pro'; Version = '10.0 (26100)'; Today = '2026-11-14'; Expected = 'EOL (2026-10)' }
        @{ OS = 'Windows 11 Pro Education'; Version = '10.0 (26100)'; Today = '2026-11-14'; Expected = 'EOL (2026-10)' }
        @{ OS = 'Windows 11 Enterprise'; Version = '10.0 (26100)'; Today = '2026-11-14'; Expected = 'Supported' }
        @{ OS = 'Windows 11 Education'; Version = '10.0 (26100)'; Today = '2027-06-01'; Expected = 'EOS 2027-10-12' }
        @{ OS = 'Windows 11 Enterprise'; Version = '10.0 (22631)'; Today = '2026-11-14'; Expected = 'EOL (2026-11)' }
        @{ OS = 'Windows 11 Pro'; Version = '10.0 (22631)'; Today = '2026-11-14'; Expected = 'EOL (2025-11)' }
        @{ OS = 'Windows 11 Pro'; Version = '10.0 (26200)'; Today = '2026-11-14'; Expected = 'Supported' }
        @{ OS = 'Windows 11 Pro'; Version = '10.0 (28000)'; Today = '2026-11-14'; Expected = 'Supported' }
        @{ OS = 'Windows 11 Pro'; Version = '10.0 (28000)'; Today = '2028-01-10'; Expected = 'EOS 2028-03-14' }
        @{ OS = 'Windows 11 Pro'; Version = '10.0 (29500)'; Today = '2026-11-14'; Expected = 'Supported' }
        @{ OS = 'Windows 11 Enterprise LTSC'; Version = '10.0 (26100)'; Today = '2026-11-14'; Expected = 'Check LTSC' }
        @{ OS = 'Windows 11 Pro'; Version = '10.0 (22500)'; Today = '2026-11-14'; Expected = 'Review' }
        @{ OS = 'Windows 11 Pro'; Version = '10.0'; Today = '2026-11-14'; Expected = 'Review' }
        @{ OS = 'Windows Server 2025 Datacenter'; Version = '10.0 (26100)'; Today = '2026-11-14'; Expected = 'Supported' }
        @{ OS = ''; Version = ''; Today = '2026-11-14'; Expected = 'Unknown' }
    ) {
        $script:Now = [datetime]$Today
        Get-OSSupport $OS $Version | Should -Be $Expected
    }

    AfterAll { $script:Now = [datetime]'2026-11-14' }
}

Describe 'Get-PatchVerdict' {
    It 'passes a DC on or above the baseline build' {
        (Get-PatchVerdict -Build '20348' -Ubr 5761 -LastPatch ([datetime]'2026-10-20') -PatchFloor '2026-10-13').Status | Should -Be 'PASS'
        (Get-PatchVerdict -Build '26100' -Ubr 33674 -LastPatch $null -PatchFloor '2026-10-13').Status | Should -Be 'PASS'
        (Get-PatchVerdict -Build '17763' -Ubr 9376 -LastPatch $null -PatchFloor '2026-10-13').Status | Should -Be 'PASS'
    }

    It 'fails a DC below the baseline build even when a later hotfix was installed recently' {
        # The v2.0.0 check used the newest hotfix date and passed this DC
        $verdict = Get-PatchVerdict -Build '20348' -Ubr 5700 -LastPatch ([datetime]'2026-11-01') -PatchFloor '2026-10-13'
        $verdict.Status | Should -Be 'FAIL'
        $verdict.Message | Should -Match '20348\.5700 is older than 20348\.5761'
    }

    It 'fails an unknown build whose newest update predates the baseline' {
        (Get-PatchVerdict -Build '9600' -Ubr 22000 -LastPatch ([datetime]'2026-09-01') -PatchFloor '2026-10-13').Status | Should -Be 'FAIL'
    }

    It 'never passes an unknown build on the hotfix date alone' {
        (Get-PatchVerdict -Build '9600' -Ubr 22000 -LastPatch ([datetime]'2026-11-01') -PatchFloor '2026-10-13').Status | Should -Be 'WARN'
        (Get-PatchVerdict -Build $null -Ubr $null -LastPatch $null -PatchFloor '2026-10-13').Status | Should -Be 'WARN'
    }
}

Describe 'Test-TgtDelegation' {
    It 'is <Expected> for trustAttributes <Value>' -ForEach @(
        @{ Value = 0x800; Expected = $true }
        @{ Value = 0x808; Expected = $true }
        @{ Value = 0xA00; Expected = $true }
        @{ Value = 0x200; Expected = $false }
        @{ Value = 0x8; Expected = $false }
        @{ Value = 0; Expected = $false }
        @{ Value = $null; Expected = $false }
    ) {
        Test-TgtDelegation $Value | Should -Be $Expected
    }
}

Describe 'Get-ReplicationHint' {
    It 'gives Exchange groups an Exchange hint, not the Entra Connect one' {
        $hint = Get-ReplicationHint 'CONTOSO\Exchange Trusted Subsystem' 'NOT a default - can read every password hash'
        $hint | Should -Match 'Exchange group'
        $hint | Should -Not -Match 'Entra'
        Get-ReplicationHint 'CONTOSO\Organization Management' 'NOT a default - can read every password hash' | Should -Match 'Exchange group'
    }
    It 'mentions a custom Entra Connect connector only for other full hash readers' {
        Get-ReplicationHint 'CONTOSO\svc-sync' 'NOT a default - can read every password hash' | Should -Match 'Entra Connect AD DS connector'
        Get-ReplicationHint 'CONTOSO\helpdesk' 'Not a default (partial right)' | Should -Be 'Remove the permission unless it is known and needed'
    }
    It 'tells you to remove leftover sync accounts' {
        Get-ReplicationHint 'CONTOSO\MSOL_0123456789ab' 'Entra Connect account whose server is gone' | Should -Match 'leftover sync account'
    }
}

Describe 'Test-LogCoversWindow' {
    It 'is <Expected> when the oldest event is <Oldest> for a <Days>-day window' -ForEach @(
        @{ Oldest = '2026-11-01'; Days = 7; Expected = $true }
        @{ Oldest = '2026-11-07'; Days = 7; Expected = $true }
        @{ Oldest = '2026-11-13 21:00'; Days = 7; Expected = $false }
        @{ Oldest = '2026-11-13 21:00'; Days = 1; Expected = $false }
    ) {
        Test-LogCoversWindow -Oldest ([datetime]$Oldest) -Days $Days | Should -Be $Expected
    }
    It 'is false when the oldest event is unknown' { Test-LogCoversWindow -Oldest $null -Days 1 | Should -BeFalse }
}

Describe 'Compress-DcdiagOutput' {
    BeforeAll {
        function New-EventBlock([string]$Time, [string]$Target) {
            '             An error event occurred.  EventID: 0x0000272C'
            "                Time Generated: 11/16/2026   $Time"
            '                Event String:'
            "                DCOM was unable to communicate with the computer $Target using any of the configured protocols; requested by PID 1c54 (C:\Program Files\Example Probe\probe.exe)."
        }
        $script:Raw = @(
            '   Testing server: Default-First-Site-Name\DC01'
            New-EventBlock '07:50:20' '192.0.2.10'
            New-EventBlock '07:50:41' '192.0.2.10'
            New-EventBlock '08:41:48' '192.0.2.1'
            New-EventBlock '08:46:53' '192.0.2.10'
            '         ......................... DC01 failed test SystemLog'
        )
    }

    It 'collapses repeated events into one block with a count and time range' {
        $out = @(Compress-DcdiagOutput $script:Raw)
        @($out | Where-Object { $_ -match 'An error event occurred' }).Count | Should -Be 2
        ($out | Where-Object { $_ -match '\(x3, first' }) | Should -Match 'first 11/16/2026 07:50:20, last 11/16/2026 08:46:53'
        @($out | Where-Object { $_ -match '\(x\d' }).Count | Should -Be 1
    }

    It 'keeps the failed test line, after the events, so the result can still be parsed' {
        $out = @(Compress-DcdiagOutput $script:Raw)
        $out[0] | Should -Match 'Testing server'
        $out[-1] | Should -Match 'DC01 failed test SystemLog'
    }

    It 'keeps the time of an event that happened once' {
        $out = @(Compress-DcdiagOutput $script:Raw)
        $single = [array]::IndexOf($out, ($out | Where-Object { $_ -match '192\.0\.2\.1 ' }))
        $out[$single - 2] | Should -Match 'Time Generated: 11/16/2026 08:41:48'
    }

    It 'leaves output without events unchanged' {
        $plain = @('   Testing server: Default-First-Site-Name\DC01', '         ......................... DC01 passed test Services')
        @(Compress-DcdiagOutput $plain) | Should -Be $plain
    }
}

Describe 'Get-DangerousRights' {
    BeforeAll {
        function New-Rule {
            param([int]$Rights, [guid]$ObjectType = [guid]::Empty, [string]$Type = 'Allow')
            [pscustomobject]@{ AccessControlType = $Type; ActiveDirectoryRights = $Rights; ObjectType = $ObjectType }
        }
        $someProperty = [guid]'bf967a7f-0de6-11d0-a285-00aa003049e2'
    }

    It 'names full control' { Get-DangerousRights (New-Rule 983551) | Should -Be @('full control') }
    It 'names change permissions and take ownership' {
        Get-DangerousRights (New-Rule (262144 + 524288)) | Should -Be @('change permissions', 'take ownership')
    }
    It 'names write all properties only when the rule covers the whole object' {
        Get-DangerousRights (New-Rule 32) | Should -Be @('write all properties')
        @(Get-DangerousRights (New-Rule 32 $someProperty)).Count | Should -Be 0
    }
    It 'ignores deny rules' { @(Get-DangerousRights (New-Rule 983551 -Type 'Deny')).Count | Should -Be 0 }
}

Describe 'Small helpers' {
    It 'Get-AgeDays counts whole days and ignores the AD "never" date' {
        Get-AgeDays ([datetime]'2026-11-04') | Should -Be 10
        Get-AgeDays ([datetime]'1601-01-01') | Should -BeNullOrEmpty
        Get-AgeDays $null | Should -BeNullOrEmpty
    }
    It 'Format-Date prints never for missing dates' {
        Format-Date ([datetime]'2026-01-05') | Should -Be '2026-01-05'
        Format-Date $null | Should -Be 'never'
    }
    It 'Limit-Text collapses whitespace and truncates' {
        Limit-Text "a  b`r`nc" | Should -Be 'a b c'
        Limit-Text ('x' * 60) 10 | Should -Be 'xxxxxxx...'
    }
    It 'parses DNs and canonical names' {
        Get-DomainFromDN 'CN=Server1,OU=Servers,DC=contoso,DC=com' | Should -Be 'contoso.com'
        Get-CnFromDN 'CN=Server1,OU=Servers,DC=contoso,DC=com' | Should -Be 'Server1'
        Get-OUPath 'contoso.com/Servers/Web/WEB01' | Should -Be 'Servers/Web'
        Get-OUPath 'contoso.com/WEB01' | Should -Be '/'
        Get-ShortName 'DC01.contoso.com' | Should -Be 'dc01'
    }
}

Describe 'Write-Status' {
    BeforeEach {
        $script:Findings = New-Object System.Collections.Generic.List[object]
        $script:Counts = @{ 'S1' = @{ PASS = 0; WARN = 0; FAIL = 0 } }
        $script:Section = 'S1'
        $script:PendingSection = $null
        $script:PendingSub = $null
    }

    It 'counts results per section and records only WARN and FAIL as findings' {
        $null = Get-HostOutput { Write-Status PASS 'ok'; Write-Status WARN 'w'; Write-Status FAIL 'f'; Write-Status INFO 'i' }
        $script:Counts['S1'].PASS | Should -Be 1
        $script:Counts['S1'].WARN | Should -Be 1
        $script:Counts['S1'].FAIL | Should -Be 1
        @($script:Findings | ForEach-Object { $_.Status }) | Should -Be @('WARN', 'FAIL')
    }
}

Describe 'Show-Table' {
    BeforeEach { $script:PendingSection = $null; $script:PendingSub = $null }

    It 'aligns columns and marks flagged rows in the margin' {
        $rows = @(
            [pscustomobject]@{ Name = 'DC01'; Free = 50 }
            [pscustomobject]@{ Name = 'DC02'; Free = 8 }
            [pscustomobject]@{ Name = 'DC03'; Free = 2 }
        )
        $out = Get-HostOutput { Show-Table $rows -Flag { param($row) if ($row.Free -lt 5) { 'FAIL' } elseif ($row.Free -lt 10) { 'WARN' } } }
        $out[0] | Should -Be '    Name  Free'
        $out[2] | Should -Be '    DC01  50'
        $out[3] | Should -Be '  ! DC02  8'
        $out[4] | Should -Be ' !! DC03  2'
    }

    It 'prints (none) for an empty table' {
        $out = Get-HostOutput { Show-Table @() }
        $out[0] | Should -Be '    (none)'
    }
}

Describe 'Get-TemplateEscProblems' {
    BeforeAll { $clientAuth = '1.3.6.1.5.5.7.3.2'; $serverAuth = '1.3.6.1.5.5.7.3.1' }

    It 'flags ESC1 when the requester chooses the subject on a logon template' {
        @(Get-TemplateEscProblems -Ekus $clientAuth -NameFlag 1 -SchemaVersion 2) -join ';' | Should -Match '^ESC1 - the requester chooses the subject'
    }
    It 'flags ESC1 when the requester supplies only the subject alternative name' {
        @(Get-TemplateEscProblems -Ekus $clientAuth -NameFlag 0x10000 -SchemaVersion 2) -join ';' | Should -Match 'ESC1 - the requester supplies the subject alternative name'
    }
    It 'counts a logon purpose found only in the application policies' {
        @(Get-TemplateEscProblems -Ekus $serverAuth -ApplicationPolicies $clientAuth -NameFlag 1 -SchemaVersion 2) -join ';' | Should -Match 'ESC1'
    }
    It 'stays quiet when manager approval or an authorised signature is required' {
        @(Get-TemplateEscProblems -Ekus $clientAuth -NameFlag 1 -EnrollmentFlag 2 -SchemaVersion 2).Count | Should -Be 0
        @(Get-TemplateEscProblems -Ekus $clientAuth -NameFlag 1 -RaSignatures 1 -SchemaVersion 2).Count | Should -Be 0
    }
    It 'treats a template with no EKU as any purpose (ESC2)' {
        @(Get-TemplateEscProblems -SchemaVersion 2) -join ';' | Should -Match 'ESC2'
    }
    It 'reports ESC17, not ESC1, for a server-only template where the requester sets the subject' {
        $found = @(Get-TemplateEscProblems -Ekus $serverAuth -NameFlag 1 -SchemaVersion 2) -join ';'
        $found | Should -Match 'ESC17'
        $found | Should -Not -Match 'ESC1 '
    }
    It 'reports ESC9 and ESC15 from their flags' {
        @(Get-TemplateEscProblems -Ekus $clientAuth -EnrollmentFlag 0x80000 -SchemaVersion 2) -join ';' | Should -Match 'ESC9'
        @(Get-TemplateEscProblems -Ekus $serverAuth -NameFlag 1 -EnrollmentFlag 2 -SchemaVersion 1) -join ';' | Should -Match 'ESC15'
    }
}

Describe 'Expand-PrivGroup' {
    BeforeAll {
        $script:DomSID = 'S-1-5-21-1-2-3'
        $script:DomDNS = 'contoso.com'
        $script:PDC = 'dc01.contoso.com'
        $script:UnsafeSids = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($s in 'S-1-1-0', 'S-1-5-11', "$($script:DomSID)-513") { [void]$script:UnsafeSids.Add($s) }
        $script:Directory = @{
            'CN=Admins,DC=contoso,DC=com'       = [pscustomobject]@{ DistinguishedName = 'CN=Admins,DC=contoso,DC=com'; Name = 'Admins'; objectClass = 'group'; sAMAccountName = 'Admins'; objectSid = "$($script:DomSID)-512"
                                                     member = @('CN=Domain Users,CN=Users,DC=contoso,DC=com', 'CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=contoso,DC=com', 'CN=Helpdesk,DC=contoso,DC=com') }
            'CN=Domain Users,CN=Users,DC=contoso,DC=com' = [pscustomobject]@{ DistinguishedName = 'CN=Domain Users,CN=Users,DC=contoso,DC=com'; Name = 'Domain Users'; objectClass = 'group'; sAMAccountName = 'Domain Users'; objectSid = "$($script:DomSID)-513"; member = @('CN=Jordan,DC=contoso,DC=com') }
            'CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=contoso,DC=com' = [pscustomobject]@{ DistinguishedName = 'CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=contoso,DC=com'; Name = 'S-1-5-11'; objectClass = 'foreignSecurityPrincipal'; sAMAccountName = $null; objectSid = $null }
            'CN=Helpdesk,DC=contoso,DC=com'     = [pscustomobject]@{ DistinguishedName = 'CN=Helpdesk,DC=contoso,DC=com'; Name = 'Helpdesk'; objectClass = 'group'; sAMAccountName = 'Helpdesk'; objectSid = "$($script:DomSID)-1105"; member = @('CN=Jordan,DC=contoso,DC=com') }
            'CN=Jordan,DC=contoso,DC=com'       = [pscustomobject]@{ DistinguishedName = 'CN=Jordan,DC=contoso,DC=com'; Name = 'Jordan'; objectClass = 'user'; sAMAccountName = 'jordan'; objectSid = "$($script:DomSID)-1106" }
        }
        # Stand-ins for the ActiveDirectory module cmdlets, which CI does not have
        function Get-ADGroup { param($Identity, $Server, $Properties) $script:Directory[$Identity] }
        function Get-ADObject { param($Identity, $Server, $Properties) $script:Directory[$Identity] }
    }

    It 'reports a nested broad group as one member instead of expanding it' {
        $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        $members = @(Expand-PrivGroup -GroupDN 'CN=Admins,DC=contoso,DC=com' -Path 'Admins' -Seen $seen)
        $domainUsers = @($members | Where-Object { $_.Name -eq 'Domain Users' })
        $domainUsers.Count | Should -Be 1
        $domainUsers[0].Class | Should -Be 'group (everyone in it)'
        $domainUsers[0].Sid | Should -Be "$($script:DomSID)-513"
    }
    It 'marks Authenticated Users stored as a foreign security principal' {
        $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        $fsp = @(Expand-PrivGroup -GroupDN 'CN=Admins,DC=contoso,DC=com' -Path 'Admins' -Seen $seen) | Where-Object { $_.Sid -eq 'S-1-5-11' }
        $fsp.Class | Should -Be 'well-known group (everyone in it)'
    }
    It 'still expands ordinary nested groups' {
        $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        $jordan = @(Expand-PrivGroup -GroupDN 'CN=Admins,DC=contoso,DC=com' -Path 'Admins' -Seen $seen) | Where-Object { $_.Sam -eq 'jordan' }
        $jordan.Via | Should -Be 'Admins > Helpdesk'
    }
}
