# Shared helpers for the Pester tests.

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
$script:ScriptPath = Join-Path $script:RepoRoot 'Invoke-ADHealthCheck.ps1'
if ($env:ADHC_SCRIPT_PATH) { $script:ScriptPath = $env:ADHC_SCRIPT_PATH }   # lets a test run point at another copy

function Get-ScriptAst {
    param([string]$Path = $script:ScriptPath)
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    if ($errors) { throw "Parse errors in ${Path}: $($errors[0].Message)" }
    return $ast
}

function Get-ScriptFunctionText {
    # The health check runs top to bottom (and needs a domain controller), so the tests load its
    # top-level functions and the top-level settings they use ($Baseline, $ADR, $EmptyGuid) from
    # the parsed file instead of running it. Functions inside the remote collector script blocks
    # are skipped on purpose.
    param([string]$Path = $script:ScriptPath)
    $ast = Get-ScriptAst $Path
    $settings = @($ast.EndBlock.Statements | Where-Object {
            $_ -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $_.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
            @('Baseline', 'ADR', 'EmptyGuid') -contains $_.Left.VariablePath.UserPath
        })
    $fns = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)
    return ((@($settings) + @($fns) | ForEach-Object { $_.Extent.Text }) -join "`n")
}

function Get-CollectorBlocks {
    # The script blocks that run on remote servers: top-level assignments of a script block
    # expression ($DCCollector, $ServerCollector, ...) plus any assigned inside a section.
    param([string]$Path = $script:ScriptPath)
    $ast = Get-ScriptAst $Path
    $ast.FindAll({
            param($n)
            $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $n.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
            $n.Left.VariablePath.UserPath -match 'Collector$'
        }, $true) | ForEach-Object {
        $block = $_.Right.Find({ param($n) $n -is [System.Management.Automation.Language.ScriptBlockExpressionAst] }, $true)
        if ($block) { [pscustomobject]@{ Name = $_.Left.VariablePath.UserPath; Ast = $block } }
    }
}

function Get-HostOutput {
    # Runs a script block and returns what it wrote with Write-Host, one string per line
    param([scriptblock]$ScriptBlock)
    $lines = New-Object System.Collections.Generic.List[string]
    & $ScriptBlock 6>&1 | ForEach-Object { $lines.Add("$_") }
    # Write-Host -NoNewline pieces arrive as separate records; the tests only look at whole rows.
    # -NoEnumerate keeps a one-line result a list, so $out[0] is a line and not its first character.
    Write-Output -NoEnumerate $lines
}
