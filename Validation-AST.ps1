<#
.SYNOPSIS
    Validation of a PowerCLI line by syntax analysis (AST), BEFORE execution. First wall of MIThrandir V2.

.DESCRIPTION
    Test-PowercliLine parses the line with the PowerShell parser and walks the complete tree. Anything that is
    not explicitly allowed is refused. If the line passes, it is rewritten to force -Server on every PowerCLI
    cmdlet that does not specify it (scope of the agent's vCenters), then fully revalidated.

    Allowed:
      - command pipelines; commands = allow-listed PowerCLI cmdlets, or utilities from the policy
      - allowed named parameters (abbreviations resolved when unambiguous), constant arguments (strings, numbers, arrays)
      - script blocks ONLY as an argument of a utility (Where-Object { ... }, Select-Object @{ N=; E={} })
        and limited to: $_ / $PSItem, property access, indexing, comparison and logical operators, constants
      - -Server with vCenter names visible to the agent
    Refused:
      - assignments, loops, conditions, functions, classes, using, try/catch
      - method calls, [types], $( ), @( ) with commands, strings with nested expressions, the & and . operators
      - redirections, pipeline chains && ||, splatting, variables other than $_ / $PSItem
      - any unknown command, alias to a non-allowed command, common parameter other than ErrorAction
#>

using namespace System.Management.Automation.Language

$Script:AllowedVariables = @('_', 'PSItem', 'true', 'false', 'null')

function ConvertTo-ServerVariableName {
    <# vc-prod-1 -> MIThrandirServer_vc_prod_1: sandbox variable holding the matching VIServer object #>
    param([string]$Name)
    return 'MIThrandirServer_' + ($Name -replace '[^A-Za-z0-9_]', '_')
}
$Script:AllowedAstTypes = @(
    [ScriptBlockAst], [NamedBlockAst], [StatementBlockAst], [PipelineAst], [CommandAst], [CommandParameterAst], [CommandExpressionAst],
    [StringConstantExpressionAst], [ConstantExpressionAst], [ExpandableStringExpressionAst], [ArrayLiteralAst], [ArrayExpressionAst],
    [ParenExpressionAst], [BinaryExpressionAst], [UnaryExpressionAst], [VariableExpressionAst], [MemberExpressionAst],
    [IndexExpressionAst], [ScriptBlockExpressionAst], [HashtableAst], [ParamBlockAst]
)

function Get-ParentCommand {
    param([Ast]$Node)
    $current = $Node.Parent
    while ($null -ne $current) {
        if ($current -is [CommandAst]) { return $current }
        $current = $current.Parent
    }
    return $null
}

function Resolve-ParameterName {
    <# Resolves a (possibly abbreviated) name to the cmdlet's exact parameter name. Returns @{ Ok; Name; Reason } #>
    param([System.Management.Automation.CommandInfo]$Command, [string]$GivenName)
    $names = @($Command.Parameters.Keys)
    $exact = $names | Where-Object { $_ -ieq $GivenName } | Select-Object -First 1
    if ($exact) { return @{ Ok = $true; Name = $exact } }
    # Parameter aliases
    foreach ($name in $names) {
        $aliases = @($Command.Parameters[$name].Aliases)
        if ($aliases | Where-Object { $_ -ieq $GivenName }) { return @{ Ok = $true; Name = $name } }
    }
    $candidates = @($names | Where-Object { $_ -ilike "$GivenName*" })
    if ($candidates.Count -eq 1) { return @{ Ok = $true; Name = $candidates[0] } }
    if ($candidates.Count -gt 1) { return @{ Ok = $false; Reason = "parameter -$GivenName ambiguous on $($Command.Name) ($($candidates -join ', '))" } }
    return @{ Ok = $false; Reason = "parameter -$GivenName unknown on $($Command.Name)" }
}

function Get-ConstantValues {
    <# Extracts the strings from a constant argument (string or array of strings). $null if the argument is not constant. #>
    param([Ast]$Argument)
    if ($Argument -is [StringConstantExpressionAst]) { return @($Argument.Value) }
    if ($Argument -is [ExpandableStringExpressionAst] -and $Argument.NestedExpressions.Count -eq 0) { return @($Argument.Value) }
    if ($Argument -is [ArrayLiteralAst]) {
        $valueList = foreach ($element in $Argument.Elements) { $v = Get-ConstantValues -Argument $element; if ($null -eq $v) { return $null }; $v }
        return @($valueList)
    }
    $pipeline = $null
    if ($Argument -is [ParenExpressionAst]) { $pipeline = $Argument.Pipeline }
    elseif ($Argument -is [ArrayExpressionAst] -and $Argument.SubExpression.Statements.Count -eq 1) { $pipeline = $Argument.SubExpression.Statements[0] }
    if ($pipeline -is [PipelineAst] -and $pipeline.PipelineElements.Count -eq 1 -and $pipeline.PipelineElements[0] -is [CommandExpressionAst]) {
        return (Get-ConstantValues -Argument $pipeline.PipelineElements[0].Expression)
    }
    return $null
}

# ---------------------------------------------------------------------------
# V4.6: property names, view paths, targeting of expensive cmdlets
# ---------------------------------------------------------------------------
$Script:PropertyParameters = @('Property', 'ExpandProperty', 'ExcludeProperty')
$Script:TargetingParameters   = @('Name', 'Id', 'Entity', 'VM', 'VMHost', 'Location', 'Datastore', 'Cluster', 'RelatedObject')

function Test-DeniedProperty {
    <#
    A property name is refused if it contains a wildcard (bypass vector: N*tes, Ext*, Not?s),
    or if it matches, segment by segment, a property of ExcludedProperties (excluded properties). Wildcards in
    property-name POSITION are always refused: the agent must name the property exactly.
    #>
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    if ($Name -match '[`*?\[\]]') { return $true }
    $excluded = @((Get-Global).ExcludedProperties)
    foreach ($segment in ($Name -split '\.')) {
        foreach ($ex in $excluded) { if ($segment -ieq $ex) { return $true } }
    }
    return $false
}

function Test-DeniedViewPath {
    <#
    Path of -Property or key of -Filter for Get-View. Refused if the path IS a forbidden path, DESCENDS from one
    (Config.ExtraConfig.X) or is an ANCESTOR of one (asking for Config would return Config.ExtraConfig). Wildcards refused.
    #>
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $true }
    if ($Path -match '[`*?\[\]]') { return $true }
    $c = $Path.Trim().TrimEnd('.')
    foreach ($forbidden in @((Get-Global).Views.ForbiddenPaths)) {
        if ($c -ieq $forbidden) { return $true }
        if ($c.StartsWith($forbidden + '.', [StringComparison]::OrdinalIgnoreCase)) { return $true }
        if ($forbidden.StartsWith($c + '.', [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

function Get-UtilityPropertyItems {
    <# Elements of a utility in property-name POSITION: -Property/-ExpandProperty/-ExcludeProperty and the
       bare positional arguments (Select/Sort/Group/Measure: positional 0 = Property; Where comparison form: same).
       Never a comparison value (-eq/-like... carry it as a named parameter). #>
    param([CommandAst]$Node, [System.Management.Automation.CommandInfo]$Info)
    # Where-Object: positional 0 = Property, positional 1 = comparison value (never a property name).
    # Select/Sort/Group/Measure: the only positional (possibly an array) is Property.
    $maxPropertyPositionals = if ($Info.Name -eq 'Where-Object') { 1 } else { [int]::MaxValue }
    $result = [System.Collections.Generic.List[Ast]]::new()
    $elements = @($Node.CommandElements | Select-Object -Skip 1)
    $i = 0; $seenPositionals = 0
    while ($i -lt $elements.Count) {
        $el = $elements[$i]
        if ($el -is [CommandParameterAst]) {
            $res = Resolve-ParameterName -Command $Info -GivenName $el.ParameterName
            $nameP = if ($res.Ok) { $res.Name } else { $el.ParameterName }
            $arg = $el.Argument
            $consumed = $false
            if ($null -eq $arg) {
                $takesValue = $true
                if ($res.Ok -and $Info.Parameters.ContainsKey($nameP)) {
                    $t = $Info.Parameters[$nameP].ParameterType
                    if ($t -eq [switch] -or $t -eq [System.Management.Automation.SwitchParameter]) { $takesValue = $false }
                }
                if ($takesValue -and ($i + 1) -lt $elements.Count -and $elements[$i + 1] -isnot [CommandParameterAst]) { $arg = $elements[$i + 1]; $consumed = $true }
            }
            if (($nameP -in $Script:PropertyParameters) -and $arg) { $result.Add($arg) }
            $i += if ($consumed) { 2 } else { 1 }
        }
        else {
            if ($seenPositionals -lt $maxPropertyPositionals) { $result.Add($el) }
            $seenPositionals++; $i++
        }
    }
    return $result
}

function Test-GetViewAllowed {
    <# Rules specific to Get-View (V4.6, Global.Views): -Property mandatory, object types and property paths bounded. #>
    param([CommandAst]$Node, [System.Management.Automation.CommandInfo]$Info)
    $views = (Get-Global).Views
    $elements = @($Node.CommandElements | Select-Object -Skip 1)
    $valueBy = @{}
    $i = 0
    while ($i -lt $elements.Count) {
        $el = $elements[$i]
        if ($el -isnot [CommandParameterAst]) { $i++; continue }
        $res = Resolve-ParameterName -Command $Info -GivenName $el.ParameterName
        if (-not $res.Ok) { return @{ Ok = $false; Reason = $res.Reason } }
        $nameP = $res.Name
        $arg = $el.Argument
        $consumed = $false
        if ($null -eq $arg -and ($i + 1) -lt $elements.Count -and $elements[$i + 1] -isnot [CommandParameterAst]) {
            $t = $Info.Parameters[$nameP].ParameterType
            if (-not ($t -eq [switch] -or $t -eq [System.Management.Automation.SwitchParameter])) { $arg = $elements[$i + 1]; $consumed = $true }
        }
        if ($nameP -eq 'Filter') {
            if ($arg -isnot [HashtableAst]) { return @{ Ok = $false; Reason = 'Get-View -Filter expects a constant hashtable' } }
            foreach ($pair in $arg.KeyValuePairs) {
                $keyNames = Get-ConstantValues -Argument $pair.Item1
                if ($null -eq $keyNames) { return @{ Ok = $false; Reason = 'Get-View -Filter: non-constant key denied' } }
                foreach ($k in @($keyNames)) { if (Test-DeniedViewPath -Path $k) { return @{ Ok = $false; Reason = "Get-View -Filter: forbidden property path: $k" } } }
                $valAst = if ($pair.Item2 -is [PipelineAst] -and $pair.Item2.PipelineElements.Count -eq 1 -and $pair.Item2.PipelineElements[0] -is [CommandExpressionAst]) { $pair.Item2.PipelineElements[0].Expression } else { $pair.Item2 }
                if ($null -eq (Get-ConstantValues -Argument $valAst)) { return @{ Ok = $false; Reason = 'Get-View -Filter: non-constant value denied' } }
            }
        }
        elseif ($arg) { $valueBy[$nameP] = @(Get-ConstantValues -Argument $arg) }
        else { $valueBy[$nameP] = @() }
        $i += if ($consumed) { 2 } else { 1 }
    }

    if ($views.MandatoryProperty -and -not $valueBy.ContainsKey('Property')) {
        return @{ Ok = $false; Reason = 'Get-View requires -Property (paths to read): a full view is too large' }
    }
    if ($valueBy.ContainsKey('Property')) {
        $paths = @($valueBy['Property'])
        if ($paths.Count -eq 0) { return @{ Ok = $false; Reason = 'Get-View -Property: at least one path' } }
        if ($paths.Count -gt [int]$views.MaxProperties) { return @{ Ok = $false; Reason = "Get-View -Property: $($paths.Count) paths, maximum $($views.MaxProperties)" } }
        foreach ($c in $paths) { if (Test-DeniedViewPath -Path $c) { return @{ Ok = $false; Reason = "Get-View -Property: forbidden path: $c" } } }
    }
    foreach ($typeKey in @('ViewType', 'Id', 'SearchRoot')) {
        if (-not $valueBy.ContainsKey($typeKey)) { continue }
        foreach ($v in @($valueBy[$typeKey])) {
            if ([string]::IsNullOrWhiteSpace($v)) { continue }
            $leType = if ($typeKey -eq 'ViewType') { $v } else { ($v -split '-', 2)[0] }
            if ($leType -notin @($views.Types)) { return @{ Ok = $false; Reason = "Get-View: object type not allowed: $leType (allowed: $(@($views.Types) -join ', '))" } }
        }
    }
    return @{ Ok = $true }
}

function Test-PowercliLine {
    <#
    Returns @{ Ok; Reason; Line (rewritten); Cmdlets (list of PowerCLI cmdlets used) }
    #>
    param(
        [Parameter(Mandatory)][string]$Line,
        [Parameter(Mandatory)][string]$IPSource,
        [switch]$AlreadyRewritten,
        [datetime]$Now = (Get-Date)
    )
    if ([string]::IsNullOrWhiteSpace($Line)) { return @{ Ok = $false; Reason = 'empty line' } }
    if ($Line.Length -gt 4000) { return @{ Ok = $false; Reason = 'line too long (4000 characters maximum)' } }
    if ($Line -match "`r|`n|`0") { return @{ Ok = $false; Reason = 'a single line, without line breaks' } }

    $tokens = $null; $errors = $null
    $tree = [Parser]::ParseInput($Line, [ref]$tokens, [ref]$errors)
    if ($errors.Count -gt 0) { return @{ Ok = $false; Reason = "invalid syntax: $($errors[0].Message)" } }
    if ($tree.ParamBlock -or $tree.BeginBlock -or $tree.ProcessBlock -or $tree.DynamicParamBlock) { return @{ Ok = $false; Reason = 'param/begin/process blocks denied' } }
    if ($tree.EndBlock.Statements.Count -ne 1) { return @{ Ok = $false; Reason = 'a single statement (one pipeline) per line' } }

    $knownVCenters = @($Script:VcenterConnections.Keys)
    $usedCmdlets = [System.Collections.Generic.List[string]]::new()
    $insertions = [System.Collections.Generic.List[hashtable]]::new()   # @{ Start (start); End; Text }: End = Start for an insertion
    $requestedServers = [System.Collections.Generic.List[string]]::new()

    foreach ($node in $tree.FindAll({ $true }, $true)) {
        $type = $node.GetType()

        if (-not ($Script:AllowedAstTypes | Where-Object { $type -eq $_ })) {
            return @{ Ok = $false; Reason = "construct denied: $($type.Name.Replace('Ast','')) ('$($node.Extent.Text)')" }
        }

        switch ($node) {
            { $_ -is [ExpandableStringExpressionAst] } {
                if ($node.NestedExpressions.Count -gt 0) { return @{ Ok = $false; Reason = "string with nested expression denied: $($node.Extent.Text)" } }
            }
            { $_ -is [VariableExpressionAst] } {
                if ($node.Splatted) { return @{ Ok = $false; Reason = 'splatting denied' } }
                $variableName = $node.VariablePath.UserPath
                $isServer = ($variableName -eq 'MIThrandirServers' -or $variableName -like 'MIThrandirServer_*')
                if ($isServer -and -not $AlreadyRewritten) { return @{ Ok = $false; Reason = 'reserved variable' } }
                if (-not $isServer -and $variableName -notin $Script:AllowedVariables) { return @{ Ok = $false; Reason = "variable denied: `$$variableName" } }
            }
            { $_ -is [MemberExpressionAst] } {
                if ($node.Static) { return @{ Ok = $false; Reason = "static access denied: $($node.Extent.Text)" } }
                if ($node.Member -isnot [StringConstantExpressionAst]) { return @{ Ok = $false; Reason = "dynamic member name denied: $($node.Extent.Text)" } }
                # V4.6: PSObject would reopen everything ($_.PSObject.Properties['Notes'].Value)
                if ($node.Member.Value -ieq 'PSObject') { return @{ Ok = $false; Reason = "access to PSObject denied: $($node.Extent.Text)" } }
                if (Test-DeniedProperty -Name ([string]$node.Member.Value)) { return @{ Ok = $false; Reason = "property excluded by the policy: $($node.Member.Value)" } }
            }
            { $_ -is [ScriptBlockExpressionAst] } {
                $parentCommand = Get-ParentCommand -Node $node
                if ($null -eq $parentCommand) { return @{ Ok = $false; Reason = 'script block outside a utility denied' } }
                $parentName = $parentCommand.GetCommandName()
                $infoParent = if ($parentName) { Get-SandboxCommand -Name $parentName } else { $null }
                if ($null -eq $infoParent -or $infoParent.Name -notin (Get-Global).Utilities) {
                    return @{ Ok = $false; Reason = "script block allowed only as an argument of $((Get-Global).Utilities -join ', ')" }
                }
                $block = $node.ScriptBlock
                if ($block.ParamBlock -or $block.BeginBlock -or $block.ProcessBlock) { return @{ Ok = $false; Reason = 'script block with param/begin/process denied' } }
            }
            { $_ -is [HashtableAst] } {
                $parentCommand = Get-ParentCommand -Node $node
                if ($null -eq $parentCommand) { return @{ Ok = $false; Reason = 'hashtable outside a utility denied' } }
                $parentName = $parentCommand.GetCommandName()
                $infoParent = if ($parentName) { Get-SandboxCommand -Name $parentName } else { $null }
                $isUtility = $infoParent -and $infoParent.Name -in (Get-Global).Utilities
                $isViewFilter  = $infoParent -and $infoParent.Name -eq 'Get-View'   # -Filter: checked by Test-GetViewAllowed
                if (-not ($isUtility -or $isViewFilter)) { return @{ Ok = $false; Reason = 'hashtable allowed only for utilities (calculated properties) and Get-View -Filter' } }
                # V4.6: in a calculated property, a string value of E=/Expression= designates a property (E='Notes')
                if ($isUtility) {
                    foreach ($pair in $node.KeyValuePairs) {
                        $keyNames = @(Get-ConstantValues -Argument $pair.Item1)
                        if (@($keyNames | Where-Object { $_ -in 'E', 'Expression' }).Count -eq 0) { continue }
                        $valAst = if ($pair.Item2 -is [PipelineAst] -and $pair.Item2.PipelineElements.Count -eq 1 -and $pair.Item2.PipelineElements[0] -is [CommandExpressionAst]) { $pair.Item2.PipelineElements[0].Expression } else { $pair.Item2 }
                        foreach ($v in @(Get-ConstantValues -Argument $valAst)) { if (Test-DeniedProperty -Name $v) { return @{ Ok = $false; Reason = "property excluded by the policy (calculated property): $v" } } }
                    }
                }
            }
            { $_ -is [CommandAst] } {
                if ($node.InvocationOperator -ne [TokenKind]::Unknown) { return @{ Ok = $false; Reason = "invocation operator denied: $($node.Extent.Text)" } }
                if ($node.Redirections.Count -gt 0) { return @{ Ok = $false; Reason = 'redirection denied' } }
                $commandName = $node.GetCommandName()
                if ([string]::IsNullOrEmpty($commandName)) { return @{ Ok = $false; Reason = "non-constant command name: $($node.Extent.Text)" } }
                if ($commandName -match '[\\/:]') { return @{ Ok = $false; Reason = "command path denied: $commandName" } }

                $info = Get-SandboxCommand -Name $commandName
                if ($null -eq $info) { return @{ Ok = $false; Reason = "unknown command: $commandName" } }
                $verdict = Test-AllowedCmdlet -Name $info.Name -Module ([string]$info.ModuleName) -IPSource $IPSource
                if (-not $verdict.Ok) { return @{ Ok = $false; Reason = $verdict.Reason } }
                if ($verdict.Type -eq 'PowerCLI') { $usedCmdlets.Add($info.Name) }

                if ($verdict.Type -eq 'Utility') {
                    # V4.6: property names (positional, -Property, -ExpandProperty, -ExcludeProperty) are
                    # checked with wildcards (N*tes), other arguments keep the exact check (defense).
                    foreach ($propertyArg in (Get-UtilityPropertyItems -Node $node -Info $info)) {
                        foreach ($value in @(Get-ConstantValues -Argument $propertyArg)) {
                            if (Test-DeniedProperty -Name $value) { return @{ Ok = $false; Reason = "property excluded by the policy: $value" } }
                        }
                    }
                    foreach ($element in $node.CommandElements | Select-Object -Skip 1) {
                        foreach ($value in @(Get-ConstantValues -Argument $element)) {
                            if ($value -in (Get-Global).ExcludedProperties) { return @{ Ok = $false; Reason = "property excluded by the policy: $value" } }
                        }
                    }
                }

                # V4.6: Get-View has its own rules (object types, property paths, -Property mandatory)
                if ($verdict.Type -eq 'PowerCLI' -and $info.Name -eq 'Get-View') {
                    $viewVerdict = Test-GetViewAllowed -Node $node -Info $info
                    if (-not $viewVerdict.Ok) { return @{ Ok = $false; Reason = $viewVerdict.Reason } }
                }

                # V4.6: targeting is mandatory for expensive cmdlets, unless they receive an upstream PowerCLI pipeline
                if ($verdict.Type -eq 'PowerCLI' -and $info.Name -in @((Get-Global).MandatoryTargeting)) {
                    $pipeline = $node.Parent
                    $position = if ($pipeline -is [PipelineAst]) { $pipeline.PipelineElements.IndexOf($node) } else { 0 }
                    if ($position -le 0) {
                        $target = $false
                        foreach ($element in $node.CommandElements | Select-Object -Skip 1) {
                            if ($element -isnot [CommandParameterAst]) { continue }
                            $r = Resolve-ParameterName -Command $info -GivenName $element.ParameterName
                            if (-not $r.Ok -or $r.Name -notin $Script:TargetingParameters) { continue }
                            $argC = $element.Argument
                            if ($null -eq $argC) { $idx = $node.CommandElements.IndexOf($element); if ($idx + 1 -lt $node.CommandElements.Count) { $argC = $node.CommandElements[$idx + 1] } }
                            $vals = @(Get-ConstantValues -Argument $argC)
                            if (@($vals | Where-Object { $_ -and $_.Trim('*', ' ') -ne '' }).Count -gt 0 -or ($argC -and $vals.Count -eq 0)) { $target = $true; break }
                        }
                        if (-not $target) { return @{ Ok = $false; Reason = "$($info.Name) requires targeting ($($Script:TargetingParameters -join ', ')) or an upstream pipeline (e.g. Get-VM -Name ... | $($info.Name)): too expensive on the whole estate" } }
                    }
                }

                $specifiedServer = $false
                foreach ($element in $node.CommandElements | Select-Object -Skip 1) {
                    if ($element -isnot [CommandParameterAst]) { continue }
                    $resolution = Resolve-ParameterName -Command $info -GivenName $element.ParameterName
                    if (-not $resolution.Ok) { return @{ Ok = $false; Reason = $resolution.Reason } }
                    $parameterName = $resolution.Name
                    if (-not (Test-AllowedParameter -Cmdlet $info.Name -Parameter $parameterName)) { return @{ Ok = $false; Reason = "parameter -$parameterName denied on $($info.Name)" } }

                    if ($parameterName -eq 'Server' -and $verdict.Type -eq 'PowerCLI') {
                        $specifiedServer = $true
                        # Value: -Server:x, -Server x, or injected by MIThrandir ($MIThrandirServers)
                        $argument = $element.Argument
                        if ($null -eq $argument) {
                            $index = $node.CommandElements.IndexOf($element)
                            if ($index + 1 -lt $node.CommandElements.Count) { $argument = $node.CommandElements[$index + 1] }
                        }
                        if ($AlreadyRewritten) {
                            $serverVariables = @($argument.FindAll({ param($n) $n -is [VariableExpressionAst] }, $true))
                            $all = ($argument -is [VariableExpressionAst]) -or ($argument -is [ArrayLiteralAst] -and @($argument.Elements | Where-Object { $_ -isnot [VariableExpressionAst] }).Count -eq 0)
                            if ($all -and $serverVariables.Count -gt 0 -and @($serverVariables | Where-Object { $_.VariablePath.UserPath -ne 'MIThrandirServers' -and $_.VariablePath.UserPath -notlike 'MIThrandirServer_*' }).Count -eq 0) { continue }
                            return @{ Ok = $false; Reason = '-Server not resolved after rewriting' }
                        }
                        $valueList = if ($argument) { Get-ConstantValues -Argument $argument } else { $null }
                        if ($null -eq $valueList -or $valueList.Count -eq 0) { return @{ Ok = $false; Reason = '-Server expects one or more short vCenter names (see Get-VIServer)' } }
                        foreach ($value in $valueList) {
                            if ($value -notin $knownVCenters) { return @{ Ok = $false; Reason = "unknown vCenter: $value (see Get-VIServer)" } }
                            if ($value -notin $requestedServers) { $requestedServers.Add($value) }
                        }
                        # Replacement of the short name(s) with the sandbox's VIServer objects
                        $variables = @($valueList | ForEach-Object { '$' + (ConvertTo-ServerVariableName -Name $_) })
                        $text = if ($variables.Count -eq 1) { $variables[0] } else { '@(' + ($variables -join ',') + ')' }
                        $insertions.Add(@{ Start = $argument.Extent.StartOffset; End = $argument.Extent.EndOffset; Text = $text })
                    }
                }
                if ($verdict.Type -eq 'PowerCLI' -and -not $specifiedServer -and $info.Parameters.ContainsKey('Server')) {
                    $insertions.Add(@{ Start = $node.CommandElements[0].Extent.EndOffset; End = $node.CommandElements[0].Extent.EndOffset; Text = ' -Server $MIThrandirServers' })
                }
            }
        }
    }

    if ($AlreadyRewritten) { return @{ Ok = $true; Reason = ''; Line = $Line; Cmdlets = @($usedCmdlets | Select-Object -Unique) } }

    # Rewrite: -Server injected where missing, short names replaced with VIServer objects, then full revalidation
    $rewritten = $Line
    foreach ($insertion in ($insertions | Sort-Object { $_.Start } -Descending)) {
        $rewritten = $rewritten.Substring(0, $insertion.Start) + $insertion.Text + $rewritten.Substring($insertion.End)
    }
    $check = Test-PowercliLine -Line $rewritten -IPSource $IPSource -AlreadyRewritten
    if (-not $check.Ok) { return @{ Ok = $false; Reason = "after rewriting: $($check.Reason)" } }

    # Rule-based decision: every cmdlet must be covered, requested vCenters must be within the resulting scope
    $cmdlets = @($check.Cmdlets)
    if ($cmdlets.Count -eq 0) { return @{ Ok = $false; Reason = 'no PowerCLI cmdlet in the line' } }
    $decision = Resolve-Decision -Subject (New-MIThrandirSubject -IP $IPSource) -Commands $cmdlets -Now $Now
    if (-not $decision.Allowed) { return @{ Ok = $false; Reason = $decision.Reason; Decision = $decision } }
    foreach ($s in $requestedServers) {
        if ($s -notin $decision.VCenters) { return @{ Ok = $false; Reason = "vCenter $s outside the scope of your rules for $($cmdlets -join ', ')"; Decision = $decision } }
    }
    if ($decision.VCenters.Count -eq 0) { return @{ Ok = $false; Reason = 'no vCenter in the scope resulting from your rules'; Decision = $decision } }
    $effectiveServers = if ($requestedServers.Count -gt 0) { @($requestedServers) } else { @($decision.VCenters) }
    return @{ Ok = $true; Reason = ''; Line = $rewritten; Cmdlets = $cmdlets; RequestedServers = @($requestedServers); Servers = $effectiveServers; Decision = $decision }
}
