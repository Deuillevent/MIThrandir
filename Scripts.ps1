<#
.SYNOPSIS
    Analysis of existing PowerShell scripts to derive a command group and a rule from them (MIThrandir V4.3).

.DESCRIPTION
    The administrator drops one or more .ps1 files (or pastes their content) into the console. MIThrandir only ANALYZES
    them (PowerShell syntax tree, never executed) and lists the commands called:
      - PowerCLI cmdlets allowed by the global allowlist: proposed for the group;
      - PowerCLI cmdlets excluded globally, or write cmdlets (Set-, New-, Remove-...): flagged, not proposed;
      - Connect-VIServer / Disconnect-VIServer: managed by MIThrandir, ignored;
      - PowerShell utilities (Where-Object, Select-Object...): accepted in pipelines, nothing to do;
      - other commands (Export-Csv, ForEach-Object, Write-Host...): not available through MIThrandir, to be adapted;
      - functions defined in the scripts themselves: ignored;
      - dynamic calls (& $x, Invoke-Expression): cannot be analyzed, flagged.
    Aliases are resolved (gci, select, where...). Literal -Server values are matched against the declared
    vCenters, to propose a scope.
#>

$Script:ViConnectionCommands = @('Connect-VIServer', 'Disconnect-VIServer', 'Connect-CisServer', 'Disconnect-CisServer')

function Get-ScriptCommandInfo {
    param([string]$Name)
    $info = $null
    if ($Script:Sandbox) { try { $info = Get-SandboxCommand -Name $Name } catch { } }
    if ($null -eq $info) { $info = Get-Command -Name $Name -ErrorAction SilentlyContinue | Select-Object -First 1 }
    if ($info -and $info.CommandType -eq 'Alias') { $info = $info.ResolvedCommand }
    return $info
}

function Invoke-ScriptAnalysis {
    param([Parameter(Mandatory)][array]$Scripts)
    if ($Scripts.Count -eq 0) { throw 'no script provided' }
    if ($Scripts.Count -gt 100) { throw 'at most 100 scripts per analysis' }
    $total = ($Scripts | ForEach-Object { ([string]$_.content).Length } | Measure-Object -Sum).Sum
    if ($total -gt 5MB) { throw 'scripts too large (at most 5 MB per analysis)' }
    $g = Get-Global
    $commands = @{}           # resolved name -> record
    $localFunctions = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $warnings = [System.Collections.Generic.List[object]]::new()
    $servers = @{}
    $resumes = [System.Collections.Generic.List[object]]::new()

    # First pass: functions defined in the scripts (they are not cmdlets to allow)
    $trees = foreach ($s in $Scripts) {
        $scriptName = [string]$s.name; if (-not $scriptName) { $scriptName = 'pasted script' }
        $tokens = $null; $errors = $null
        $tree = [System.Management.Automation.Language.Parser]::ParseInput([string]$s.content, [ref]$tokens, [ref]$errors)
        if ($errors.Count -gt 0) { $warnings.Add([ordered]@{ script = $scriptName; line = $errors[0].Extent.StartLineNumber; message = "syntax error: $($errors[0].Message) (partial analysis)" }) }
        foreach ($f in $tree.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) { [void]$localFunctions.Add($f.Name) }
        [pscustomobject]@{ Name = $scriptName; Tree = $tree; Lines = ([string]$s.content -split "`n").Count }
    }

    foreach ($a in $trees) {
        $calls = @($a.Tree.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true))
        $resumes.Add([ordered]@{ name = $a.Name; lines = $a.Lines; calls = $calls.Count })
        foreach ($call in $calls) {
            $line = $call.Extent.StartLineNumber
            $rawName = $call.GetCommandName()
            if ($call.InvocationOperator -ne [System.Management.Automation.Language.TokenKind]::Unknown -and -not $rawName) {
                $warnings.Add([ordered]@{ script = $a.Name; line = $line; message = "dynamic call, cannot be analyzed: $($call.Extent.Text.Substring(0, [math]::Min(80, $call.Extent.Text.Length)))" }); continue
            }
            if (-not $rawName) { continue }
            if ($rawName -in @('Invoke-Expression', 'iex')) { $warnings.Add([ordered]@{ script = $a.Name; line = $line; message = 'Invoke-Expression: dynamic content, cannot be analyzed (and denied by MIThrandir)' }) }
            if ($localFunctions.Contains($rawName)) { continue }

            $info = Get-ScriptCommandInfo -Name $rawName
            $name = if ($info) { $info.Name } else { $rawName }
            $module = if ($info -and $info.ModuleName) { [string]$info.ModuleName } else { '' }
            if (-not $commands.ContainsKey($name)) {
                $status =
                    if ($name -in $Script:ViConnectionCommands) { 'connection' }
                    elseif ($name -in $g.Utilities) { 'utility' }
                    elseif (-not $info) { 'unknown' }
                    elseif ($module -like 'VMware.*') {
                        if ($name -in $g.ExcludedCmdlets) { 'excluded' }
                        elseif (-not (Test-PatternList -Value $name -Patterns $g.AllowedCmdlets)) { if ($name -like 'Get-*') { 'excluded' } else { 'write' } }
                        else { 'isAllowed' }
                    }
                    else { 'outside-powercli' }
                $commands[$name] = [ordered]@{ name = $name; alias = [System.Collections.Generic.List[string]]::new(); module = $module; status = $status; occurrences = 0; scripts = [System.Collections.Generic.List[string]]::new(); parameters = [System.Collections.Generic.List[string]]::new(); lines = [System.Collections.Generic.List[string]]::new() }
            }
            $sheet = $commands[$name]
            $sheet.occurrences++
            if ($rawName -ne $name -and -not $sheet.alias.Contains($rawName)) { $sheet.alias.Add($rawName) }
            if (-not $sheet.scripts.Contains($a.Name)) { $sheet.scripts.Add($a.Name) }
            if ($sheet.lines.Count -lt 5) { $sheet.lines.Add("$($a.Name):$line") }
            $elements = $call.CommandElements
            for ($i = 1; $i -lt $elements.Count; $i++) {
                if ($elements[$i] -isnot [System.Management.Automation.Language.CommandParameterAst]) { continue }
                $p = $elements[$i].ParameterName
                if ($info -and $info.Parameters) {
                    $full = @($info.Parameters.Keys | Where-Object { $_ -like "$p*" })
                    if ($full.Count -eq 1) { $p = $full[0] } elseif ($info.Parameters.ContainsKey($p)) { $p = $p }
                }
                if (-not $sheet.parameters.Contains($p)) { $sheet.parameters.Add($p) }
                if ($p -eq 'Server') {
                    $value = if ($elements[$i].Argument) { $elements[$i].Argument } elseif ($i + 1 -lt $elements.Count) { $elements[$i + 1] } else { $null }
                    if ($value -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $servers[$value.Value] = $true }
                    elseif ($value) { $servers['(variable: ' + $value.Extent.Text + ')'] = $true }
                }
            }
        }
    }

    # Matching literal -Server values against the declared vCenters (short name or address)
    $vcenters = @(foreach ($v in @($servers.Keys)) {
        $found = @($Script:VcenterConnections.Values | Where-Object { $_.Name -eq $v -or $_.Config.Server -eq $v }) | Select-Object -First 1
        [ordered]@{ value = $v; vcenter = if ($found) { $found.Name } else { '' } }
    })
    $excludedParameters = @($g.ExcludedParameters)
    $list = @($commands.Values | Sort-Object { @{ isAllowed = 0; excluded = 1; write = 2; 'outside-powercli' = 3; unknown = 4; connection = 5; utility = 6 }[$_.status] }, { $_.name } | ForEach-Object {
        $_.deniedParameters = @($_.parameters | Where-Object { $_ -in $excludedParameters })
        $_
    })
    return [ordered]@{
        scripts = @($resumes); cmdlets = $list; localFunctions = @($localFunctions); servers = $vcenters
        warnings = @($warnings | Select-Object -First 50)
        resume = [ordered]@{
            allowed = @($list | Where-Object { $_.status -eq 'isAllowed' }).Count; excluded = @($list | Where-Object { $_.status -eq 'excluded' }).Count
            write = @($list | Where-Object { $_.status -eq 'write' }).Count; nonPowerCli = @($list | Where-Object { $_.status -eq 'outside-powercli' }).Count
            unknown = @($list | Where-Object { $_.status -eq 'unknown' }).Count
        }
    }
}
