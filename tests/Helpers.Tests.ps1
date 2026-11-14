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
        @{ Value = 0xA00; Expected = $false }
        @{ Value = 0x8; Expected = $false }
        @{ Value = 0; Expected = $false }
        @{ Value = $null; Expected = $false }
    ) {
        Test-TgtDelegation $Value | Should -Be $Expected
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
