# Whole-script checks: it parses, stays plain ASCII, makes no changes, and its remote
# script blocks can run on another server without the helper functions.

BeforeDiscovery {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
}

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Ast = Get-ScriptAst
    $script:Commands = @($script:Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true))
}

Describe 'Script file' {
    It 'parses without errors' {
        $errors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$null, [ref]$errors)
        $errors.Count | Should -Be 0
    }

    It 'is plain ASCII (Windows PowerShell 5.1 reads a file without a BOM as ANSI)' {
        $latin1 = [IO.File]::ReadAllText($script:ScriptPath, [Text.Encoding]::GetEncoding(28591))
        $latin1 -match '[^\x00-\x7F]' | Should -BeFalse
    }

    It 'has help with an example for every parameter' {
        $help = $script:Ast.GetHelpContent()
        $help.Synopsis | Should -Not -BeNullOrEmpty
        $help.Examples.Count | Should -BeGreaterThan 0
        foreach ($p in $script:Ast.ParamBlock.Parameters) {
            $help.Parameters.Keys | Should -Contain $p.Name.VariablePath.UserPath.ToUpper()
        }
    }

    It 'declares a semantic version' {
        $version = $script:Ast.EndBlock.Statements | Where-Object {
            $_ -is [System.Management.Automation.Language.AssignmentStatementAst] -and "$($_.Left)" -eq '$ScriptVersion'
        }
        "$($version.Right)" | Should -Match "^'\d+\.\d+\.\d+'$"
    }
}

Describe 'Read-only' {
    It 'calls only commands that read, plus its own session and job cleanup' {
        $readVerbs = '^(Get|Test|Resolve|Select|Sort|Where|ForEach|Group|Measure|Compare|ConvertFrom|ConvertTo|Format|Limit|Show|Expand|Receive|Wait|Join|Out|Import)-'
        $allowed = @(
            'Add-Member', 'New-Object', 'New-PSSession', 'New-PSSessionOption', 'Remove-PSSession', 'Remove-Job', 'Stop-Job',
            'Invoke-Command', 'Invoke-Native', 'Invoke-OnComputer', 'Compress-DcdiagOutput',
            'Write-Host', 'Write-Progress', 'Write-Status', 'Write-Section', 'Write-Sub', 'Write-Info', 'Write-Detail', 'Write-HeaderLines',
            'w32tm.exe', 'auditpol.exe'
        )
        $unexpected = @($script:Commands | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ } | Sort-Object -Unique |
                Where-Object { $_ -notmatch $readVerbs -and $allowed -notcontains $_ })
        $unexpected | Should -BeNullOrEmpty
    }

    It 'runs native tools only with read-only arguments' {
        $denied = '/sync|/kcc|/resync|/setglobalstate|-setreg|-delreg|/fix|/register|/unregister|/set\b|/clear|/remove|/delete|/rehost|/resync'
        $native = @($script:Commands | Where-Object { $_.GetCommandName() -eq 'Invoke-Native' -or "$($_.GetCommandName())" -match '\.exe$' })
        $native.Count | Should -BeGreaterThan 0
        foreach ($call in $native) { $call.Extent.Text | Should -Not -Match $denied }
        $exes = @($native | Where-Object { $_.GetCommandName() -eq 'Invoke-Native' } | ForEach-Object {
                if ($_.Extent.Text -match "-Exe\s+'([^']+)'") { $Matches[1] } else { '(dynamic)' } } | Sort-Object -Unique)
        $exes | Should -Be @('certutil.exe', 'dcdiag.exe', 'dfsrmig.exe', 'repadmin.exe', 'w32tm.exe')
    }

    It 'never writes to the registry, files or AD through .NET' {
        $text = [IO.File]::ReadAllText($script:ScriptPath)
        $text | Should -Not -Match '\.SetValue\(|\.CreateSubKey\(|\.DeleteValue\(|\.CommitChanges\(|WriteAllText|AppendAllText|\.SetAccessRule|\.AddAccessRule|\.SetOwner\('
    }
}

Describe 'Remote collectors' {
    It 'finds the collector script blocks' {
        @(Get-CollectorBlocks).Count | Should -BeGreaterOrEqual 3
    }

    It '<Name> calls no helper defined outside it (it runs on another server)' -ForEach @(
        Get-CollectorBlocks | ForEach-Object { @{ Name = $_.Name; Block = $_.Ast } }
    ) {
        $topLevel = @($script:Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false) | ForEach-Object { $_.Name })
        $inside = @($Block.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object { $_.Name })
        $called = @($Block.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
        $missing = @($called | Where-Object { $topLevel -contains $_ -and $inside -notcontains $_ } | Sort-Object -Unique)
        $missing | Should -BeNullOrEmpty
    }
}

Describe 'Script-scope state' {
    It 'is never overwritten by a top-level variable of the same name' {
        # Variable names ignore case, and at the top level of the script $counts IS $script:Counts.
        # In 2.1.0 the section 5 GPO folder table ($counts) replaced the PASS/WARN/FAIL tally and the
        # next Write-Status call stopped the run. Top-level code must use different names.
        $L = [System.Management.Automation.Language.VariableExpressionAst]
        $state = @($script:Ast.FindAll({ param($n) $n -is $L -and $n.VariablePath.IsScript }, $true) |
                ForEach-Object { ($_.VariablePath.UserPath -replace '^script:', '').ToLower() } | Sort-Object -Unique)
        $state.Count | Should -BeGreaterThan 5

        $topLevel = @($script:Ast.FindAll({
                    param($n)
                    ($n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left -is $L) -or
                    $n -is [System.Management.Automation.Language.ForEachStatementAst]
                }, $true) | Where-Object {
                $p = $_.Parent
                $isTop = $true
                while ($p) {
                    if ($p -is [System.Management.Automation.Language.FunctionDefinitionAst] -or $p -is [System.Management.Automation.Language.ScriptBlockExpressionAst]) { $isTop = $false; break }
                    $p = $p.Parent
                }
                $isTop
            })
        $clashes = @(foreach ($node in $topLevel) {
                if ($node -is [System.Management.Automation.Language.ForEachStatementAst]) { $v = $node.Variable } else { $v = $node.Left }
                if (-not $v.VariablePath.IsScript -and $state -contains $v.VariablePath.UserPath.ToLower()) { "line $($node.Extent.StartLineNumber): `$$($v.VariablePath.UserPath)" }
            })
        $clashes | Should -BeNullOrEmpty
    }
}
