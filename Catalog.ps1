<#
.SYNOPSIS
    Catalog of MIThrandir V2 MCP tools.

.DESCRIPTION
      - Get-MIThrandirTime : link diagnostic
      - Get-VIServer     : vCenters visible to the agent
      - Invoke-PowerCLI  : one complete PowerCLI line (pipeline included), validated by AST then run in the sandbox
      - one tool per cmdlet of Policy.TypedTools, whose schema is GENERATED from the installed cmdlet
        (names, types, ValidateSet, mandatory): parity with PowerCLI is guaranteed by construction.
        The call is turned into a PowerCLI line and follows exactly the same path as Invoke-PowerCLI.

    All tools have Level 'Read': the policy only allows Get-* cmdlets.
    Each Action receives ($Arguments, $Context); $Context.IPSource identifies the agent.
#>

function ConvertTo-LiteralPowerShell {
    <# Turns a JSON value into a safe PowerShell literal, according to the PowerCLI parameter type. #>
    param($Value, [type]$ParameterType)
    $isArray = $ParameterType.IsArray
    $typeElement = if ($isArray) { $ParameterType.GetElementType() } else { $ParameterType }

    if ($typeElement -eq [switch] -or $typeElement -eq [System.Management.Automation.SwitchParameter]) { return $null }   # handled separately
    $elements = @(if ($Value -is [System.Collections.IList] -and $Value -isnot [string]) { @($Value) } else { @($Value) })
    $literals = foreach ($element in $elements) {
        if ($null -eq $element) { continue }
        if ($typeElement -eq [bool])                                          { if ([bool]$element) { '$true' } else { '$false' }; continue }
        if ($typeElement -in @([int], [long], [int16], [uint32], [uint64]))   { ([long]$element).ToString(); continue }
        if ($typeElement -in @([double], [single], [decimal]))               { ([double]$element).ToString([cultureinfo]::InvariantCulture); continue }
        if ($typeElement -eq [datetime])                                      { "'" + ([datetime]$element).ToString('o') + "'"; continue }
        # strings, enums, PowerCLI objects by name (OBN): single-quoted literal
        "'" + ([string]$element).Replace("'", "''") + "'"
    }
    $literals = @($literals)
    if ($literals.Count -eq 0) { return $null }
    if ($literals.Count -eq 1 -and -not $isArray) { return $literals[0] }
    return ($literals -join ',')
}

function ConvertTo-ParameterSchema {
    param([System.Management.Automation.ParameterMetadata]$Parameter, [bool]$Mandatory)
    $type = $Parameter.ParameterType
    $typeElement = if ($type.IsArray) { $type.GetElementType() } else { $type }
    $schema = [ordered]@{}
    $description = ''

    if ($typeElement -eq [System.Management.Automation.SwitchParameter]) { $schema.type = 'boolean'; $description = 'Switch.' }
    elseif ($typeElement -eq [bool])                                          { $schema.type = 'boolean' }
    elseif ($typeElement -in @([int], [long], [int16], [uint32], [uint64])) { $schema.type = 'integer' }
    elseif ($typeElement -in @([double], [single], [decimal]))               { $schema.type = 'number' }
    elseif ($typeElement.IsEnum) {
        $schema.type = 'string'; $schema.enum = @([enum]::GetNames($typeElement))
    }
    elseif ($typeElement -eq [string]) { $schema.type = 'string'; $description = if ($Parameter.Name -eq 'Name') { 'Wildcards * and ? accepted.' } else { '' } }
    elseif ($typeElement -eq [datetime]) { $schema.type = 'string'; $description = 'Date/time ISO 8601.' }
    else {
        # PowerCLI object (VirtualMachine, VIContainer, Datastore, ...): PowerCLI accepts its NAME (Object-By-Name), wildcards included
        $schema.type = 'string'
        $description = "Name of a $($typeElement.Name) object (wildcards accepted)."
    }
    if ($Parameter.Name -eq 'Server') { $description = 'Short vCenter name (see Get-VIServer). Omitted = all allowed vCenters.' }
    $set = $Parameter.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] } | Select-Object -First 1
    if ($set) { $schema.enum = @($set.ValidValues) }
    if ($type.IsArray -and $schema.type -ne 'boolean') { $description = ($description + ' Multiple values: JSON array.').Trim() }
    if ($Mandatory) { $description = ('Mandatory. ' + $description).Trim() }
    if ($description) { $schema.description = $description }
    return $schema
}

function New-ToolType {
    <# Builds an MCP tool from the CommandInfo of a sandbox cmdlet. #>
    param([System.Management.Automation.CommandInfo]$Command)
    $properties = [ordered]@{}
    $mandatoryList = [System.Collections.Generic.List[string]]::new()
    $defaultSet = $Command.ParameterSets | Where-Object { $_.IsDefault } | Select-Object -First 1
    foreach ($name in ($Command.Parameters.Keys | Sort-Object)) {
        if (-not (Test-AllowedParameter -Cmdlet $Command.Name -Parameter $name)) { continue }
        if ($name -eq 'ErrorAction') { continue }
        $parameter = $Command.Parameters[$name]
        $mandatory = $false
        if ($defaultSet) {
            $inSet = $defaultSet.Parameters | Where-Object { $_.Name -eq $name } | Select-Object -First 1
            if ($inSet -and $inSet.IsMandatory) { $mandatory = $true }
        }
        $properties[$name] = ConvertTo-ParameterSchema -Parameter $parameter -Mandatory $mandatory
        if ($mandatory) { $mandatoryList.Add($name) }
    }
    $properties['Limit'] = @{ type = 'integer'; description = "MIThrandir-specific (not a PowerCLI parameter): maximum objects returned (1 to $((Get-Global).MaxBatchSize), default $((Get-Global).DefaultBatchSize))."; minimum = 1; maximum = (Get-Global).MaxBatchSize }

    $synopsis = ''
    try { $help = Get-Help $Command.Name -ErrorAction SilentlyContinue; if ($help -and $help.Synopsis -and ($help.Synopsis -notmatch ('^\s*' + [regex]::Escape($Command.Name)))) { $synopsis = ([string]$help.Synopsis).Trim() } } catch { }
    $description = "PowerCLI cmdlet $($Command.Name), same parameters as the original (read only). $synopsis Each returned object carries its source vCenter; paged result (Limit)."
    $schema = @{ type = 'object'; properties = $properties; additionalProperties = $false }
    if ($mandatoryList.Count -gt 0) { $schema.required = @($mandatoryList) }

    $cmdletName = $Command.Name
    return @{
        Name = $cmdletName; Title = $cmdletName; Level = 'Read'; Description = $description; InputSchema = $schema
        Command = $Command
        Action = {
            param([hashtable]$Arguments, [hashtable]$Context)
            $tool = $Script:Catalog | Where-Object { $_.Name -eq $Context.ToolName } | Select-Object -First 1
            $command = $tool.Command
            $chunks = [System.Collections.Generic.List[string]]::new()
            $chunks.Add($command.Name)
            foreach ($key in $Arguments.Keys) {
                if ($key -eq 'Limit') { continue }
                if (-not $command.Parameters.ContainsKey($key)) { throw "unknown parameter: $key" }
                $parameter = $command.Parameters[$key]
                $value = $Arguments[$key]
                if ($parameter.ParameterType -eq [System.Management.Automation.SwitchParameter]) {
                    if ([bool]$value) { $chunks.Add("-$key") }
                    continue
                }
                $literal = ConvertTo-LiteralPowerShell -Value $value -ParameterType $parameter.ParameterType
                if ($null -ne $literal) { $chunks.Add("-$key $literal") }
            }
            $line = $chunks -join ' '
            return Invoke-PowercliLine -Line $line -Context $Context -Limit (Get-BatchSize -Arguments $Arguments)
        }
    }
}

function Invoke-PowercliLine {
    <# Common path: AST validation, reconnection of the target vCenters, execution in the sandbox, bounding of the output. #>
    param([Parameter(Mandatory)][string]$Line, [Parameter(Mandatory)][hashtable]$Context, [int]$Limit = 25)
    $validation = Test-PowercliLine -Line $Line -IPSource $Context.IPSource
    if (-not $validation.Ok) {
        Write-Journal -Level 'DENIED' -Message "Line denied: $($validation.Reason)" -Data @{ ip = $Context.IPSource; line = $Line }
        throw "line denied by MIThrandir: $($validation.Reason)"
    }
    $servers = @($validation.Servers | Where-Object { Assert-VcenterConnection -Name $_ })
    if ($servers.Count -eq 0) { throw 'no vCenter available for this call' }

    # V4.6: sandbox time budget per agent (bounds the load of a single agent, regardless of the number of calls)
    $agentKey = Get-AgentKey -IP $Context.IPSource
    $budget = Test-SandboxSecondsBudget -Key $agentKey
    if (-not $budget.Ok) {
        Write-Journal -Level 'DENIED' -Message "Sandbox time budget exhausted: $($budget.Reason)" -Data @{ ip = $Context.IPSource; line = $Line }
        throw "line denied by MIThrandir: $($budget.Reason)"
    }

    # Scope inside the vCenters (V4.4): filter inserted after each PowerCLI cmdlet
    $executedLine = $validation.Line
    $filter = Get-ScopeFilter -Decision $validation.Decision -VCenters $servers
    if ($filter.Restricted) {
        $insertion = Add-ScopeFilterLine -Line $executedLine
        if (-not $insertion.Ok) {
            Write-Journal -Level 'DENIED' -Message "Line denied: $($insertion.Reason)" -Data @{ ip = $Context.IPSource; line = $Line }
            throw "line denied by MIThrandir: $($insertion.Reason)"
        }
        $executedLine = $insertion.Line
    }
    Write-Journal -Level 'CALL' -Message 'Execution PowerCLI' -Data @{ ip = $Context.IPSource; line = $validation.Line; cmdlets = $validation.Cmdlets; servers = $servers; rules = @($validation.Decision.Rules.Id); filterScope = $filter.Restricted; vmScope = $(if ($filter.Restricted) { $filter.VmCount } else { $null }) }
    $sandboxTimer = [System.Diagnostics.Stopwatch]::StartNew()
    $result = Invoke-InSandbox -Line $executedLine -Servers $servers -Limit $Limit -Filter $filter
    $sandboxTimer.Stop()
    Add-SandboxSeconds -Key $agentKey -Seconds ($sandboxTimer.Elapsed.TotalSeconds)
    if (-not $result.Interrupted) { Register-Execution -Decision $validation.Decision -Subject @{ IP = $Context.IPSource } }

    $response = [ordered]@{ executedLine = $Line; queriedVCenters = $servers; rules = @($validation.Decision.Rules.Id) }
    if ($filter.Restricted) {
        $response.scope = [ordered]@{ filter = $true; visibleVms = $filter.VmCount; infrastructureVisible = $filter.InfraVisible; wholeVCenters = @($filter.FreeVCenters)
            note = "only VMs in the agent's scope are visible (computed from the MIThrandir inventory); a VM created since the last inventory cycle does not appear yet" }
        if ($filter.Warnings.Count -gt 0) { $response.scope.warnings = @($filter.Warnings) }
    }
    if ($result.Interrupted) { $response.error = "timeout of $((Get-Global).MaxDelaySeconds) s exceeded, execution interrupted"; return $response }
    if ($result.Errors.Count -gt 0) { $response.errors = @($result.Errors | Select-Object -First 5) }
    if ($result.Output.Count -gt 0) {
        $projection = $result.Output[-1]
        foreach ($key in @('total', 'returned', 'truncated', 'objects')) { if ($projection.Contains($key)) { $response[$key] = $projection[$key] } }
    }
    else { $response.total = 0; $response.returned = 0; $response.truncated = $false; $response.objects = @() }
    return $response
}

function Get-ToolCatalog {
    param([switch]$WithVCenter)
    $catalog = [System.Collections.Generic.List[hashtable]]::new()

    $catalog.Add(@{
        Name = 'Get-MIThrandirTime'; Title = 'MIThrandir time'; Level = 'Read'
        Description = 'Returns the date, time and name of the machine hosting MIThrandir. Use it to check the agent / MIThrandir connection.'
        InputSchema = @{ type = 'object'; properties = @{}; additionalProperties = $false }
        Action = {
            param([hashtable]$Arguments, [hashtable]$Context)
            if ($Context.ContainsKey('Decision') -and $Context.Decision) { Register-Execution -Decision $Context.Decision -Subject @{ IP = $Context.IPSource } }
            [ordered]@{ localTime = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'); utcTime = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss'); machine = $env:COMPUTERNAME; gateway = 'MIThrandir V4'; vcenters = $Script:VcenterConnections.Count }
        }
    })

    # Discovery of the engine's capabilities (global, not sensitive): what the agent can do, and the limits.
    # Subject to the rules like the other non-PowerCLI tools; covered by default by the diagnostic-mithrandir group.
    $catalog.Add(@{
        Name = 'Get-MIThrandirCapabilities'; Title = 'MIThrandir capabilities'; Level = 'Read'
        Description = "Describes how to talk to MIThrandir and its limits: call format, allowed cmdlets and utilities, limits (batch size, output size, timeouts, time budget), forbidden parameters and properties, mandatory targeting, Get-View restrictions. Does NOT show the agent's own rights (see Get-MIThrandirMyRights). Read it to learn which commands exist before trying one."
        InputSchema = @{ type = 'object'; properties = @{}; additionalProperties = $false }
        Action = {
            param([hashtable]$Arguments, [hashtable]$Context)
            if ($Context.ContainsKey('Decision') -and $Context.Decision) { Register-Execution -Decision $Context.Decision -Subject @{ IP = $Context.IPSource } }
            Write-Journal -Level 'INFO' -Message 'Capability discovery (Get-MIThrandirCapabilities)' -Data @{ ip = $Context.IPSource }
            $g = Get-Global
            $views = if ($g.ContainsKey('Views')) { $g.Views } else { @{} }
            [ordered]@{
                gateway = 'MIThrandir V4'
                call = [ordered]@{
                    mainTool = 'Invoke-PowerCLI'
                    note = "Agents write ONE PowerCLI line (pipeline included) through Invoke-PowerCLI, or call a typed tool (below). No variables, assignments, loops, methods or [types]."
                    typedTools = @($g.TypedTools)
                    serviceTools = @('Get-MIThrandirTime', 'Get-VIServer', 'Get-MIThrandirCapabilities', 'Get-MIThrandirMyRights') + $(if ($Script:Inventory.active) { @('Get-MIThrandirInventory') } else { @() })
                }
                allowList = [ordered]@{
                    allowedCmdlets = @($g.AllowedCmdlets)
                    excludedCmdlets    = @($g.ExcludedCmdlets)
                    utilities       = @($g.Utilities)
                    writeAllowed = [bool]$g.AllowWrite
                    note = 'Connection/session cmdlets (Connect-VIServer, Disconnect-VIServer, Set-PowerCLIConfiguration...) are ALWAYS denied and invisible: MIThrandir manages the sessions.'
                }
                limits = [ordered]@{
                    defaultObjectsPerResponse = $g.DefaultBatchSize
                    maxObjectsPerResponse    = $g.MaxBatchSize
                    defaultBatchSize   = $g.DefaultBatchSize   # backward-compatible alias
                    maxBatchSize      = $g.MaxBatchSize      # backward-compatible alias
                    maxOutputSizeChars = $g.MaxOutputSize
                    maxDelaySeconds  = $g.MaxDelaySeconds
                    sandboxSecondsPerHour = $g.SandboxSecondsPerHour
                    defaultCallQuotaPerHour = $g.DefaultCallQuotaPerHour
                    note = "MIThrandir returns at most $($g.DefaultBatchSize) objects by default and $($g.MaxBatchSize) at most: pass the Limit parameter (1 to $($g.MaxBatchSize)) to request more, never beyond $($g.MaxBatchSize). The response is ALSO capped at $($g.MaxOutputSize) characters: beyond that it is truncated even below $($g.MaxBatchSize) objects, so target the request and ask only for the useful properties (Select-Object). Beyond $($g.MaxDelaySeconds) s, execution is interrupted."
                }
                constraints = [ordered]@{
                    hiddenProperties    = @($g.ExcludedProperties)
                    excludedParameters      = @($g.ExcludedParameters)
                    mandatoryTargeting    = @($g.MandatoryTargeting)
                    note = "hiddenProperties: never returned, whatever the object. mandatoryTargeting: these expensive cmdlets must be targeted (-Name/-Id/-Entity/-VM/-Location) or receive an upstream PowerCLI pipeline."
                }
                views = [ordered]@{
                    note = "Get-View is allowed but bounded: -Property MANDATORY, object types on an allow list, some paths forbidden."
                    maxProperties  = if ($views.ContainsKey('MaxProperties')) { $views.MaxProperties } else { $null }
                    allowedTypes = if ($views.ContainsKey('Types')) { @($views.Types) } else { @() }
                    forbiddenPaths = if ($views.ContainsKey('ForbiddenPaths')) { @($views.ForbiddenPaths) } else { @() }
                }
            }
        }
    })

    if (-not $WithVCenter) { return $catalog }

    $catalog.Add(@{
        Name = 'Get-VIServer'; Title = 'vCenters connected'; Level = 'Read'
        Description = 'Lists the vCenters the agent can query: short name (value for the -Server parameter), FQDN, version, build, state. Call this first.'
        InputSchema = @{ type = 'object'; properties = @{}; additionalProperties = $false }
        Action = {
            param([hashtable]$Arguments, [hashtable]$Context)
            if ($Context.ContainsKey('Decision') -and $Context.Decision) { Register-Execution -Decision $Context.Decision -Subject @{ IP = $Context.IPSource } }
            $list = @(foreach ($name in (Get-AllowedVCenters -IPSource $Context.IPSource)) {
                $entry = $Script:VcenterConnections[$name]
                $active = [bool]($entry.Connection -and $entry.Connection.IsConnected)
                [ordered]@{
                    name = $name; server = $entry.Config.Server
                    version = if ($entry.Connection) { $entry.Connection.Version } else { $null }
                    build   = if ($entry.Connection) { $entry.Connection.Build } else { $null }
                    state    = if ($active) { 'connected' } elseif ($entry.Connection) { 'session expired (reconnects on next call)' } else { "unavailable: $($entry.Error)" }
                }
            })
            [ordered]@{ quantity = $list.Count; vcenters = $list }
        }
    })

    # RSoP (resultant set of policy) of the calling agent: what it is allowed to do, as the outcome of its rules.
    $catalog.Add(@{
        Name = 'Get-MIThrandirMyRights'; Title = 'My rights'; Level = 'Read'
        Description = "Summarizes what THIS agent is allowed to do right now: effectively allowed cmdlets (after Deny rules are applied), reachable vCenters, remaining quotas, and number of objects returned per response. Read it to avoid trying a command outside your scope. Complements Get-MIThrandirCapabilities (which describes the general limits of the engine)."
        InputSchema = @{ type = 'object'; properties = @{}; additionalProperties = $false }
        Action = {
            param([hashtable]$Arguments, [hashtable]$Context)
            if ($Context.ContainsKey('Decision') -and $Context.Decision) { Register-Execution -Decision $Context.Decision -Subject @{ IP = $Context.IPSource } }
            Write-Journal -Level 'INFO' -Message 'Rights discovery (Get-MIThrandirMyRights)' -Data @{ ip = $Context.IPSource }
            $g = Get-Global
            $subject = New-MIThrandirSubject -IP $Context.IPSource
            $applicable = @(Get-ApplicableRules -Subject $subject)
            $autor = @($applicable | Where-Object { $_.Effect -eq 'Allow' })
            $denial = @($applicable | Where-Object { $_.Effect -eq 'Deny' })

            # Cmdlets covered by an Allow, minus those neutralized by a Deny (on the command, like the engine)
            $allowedPatterns = @($autor | ForEach-Object { Get-RuleCmdlets -Rule $_ } | Select-Object -Unique)
            $denialPatterns = @($denial | ForEach-Object { Get-RuleCmdlets -Rule $_ } | Select-Object -Unique)
            $isDenied = {
                param($c)
                foreach ($m in $denialPatterns) { if ($c -eq $m -or (Test-PatternList -Value $c -Patterns @($m))) { return $true } }
                return $false
            }
            $effectiveCmdlets = @($allowedPatterns | Where-Object { -not (& $isDenied $_) } | Sort-Object)
            $neutralizedCmdlets = @($allowedPatterns | Where-Object { & $isDenied $_ } | Sort-Object)

            # Service tools allowed for this agent (among the non-PowerCLI ones)
            $serviceTools = @(foreach ($o in @('Get-MIThrandirTime', 'Get-VIServer', 'Get-MIThrandirCapabilities', 'Get-MIThrandirMyRights')) {
                $d = Resolve-Decision -Subject $subject -Commands @($o) -NoQuota
                if ($d.Allowed) { $o }
            })

            # Remaining quotas per retained Allow rule (per-agent limit)
            $quotas = @(foreach ($r in $autor) {
                $remaining = Get-RuleQuotaRemaining -Rule $r -IP $Context.IPSource
                [ordered]@{ rule = $r.Id; name = $r.Name; perHour = [int]$r.Limits.CallQuotaPerHour; remaining = $(if ($remaining -lt 0) { 'unlimited' } else { $remaining }) }
            })

            [ordered]@{
                agent = $Context.IPSource
                account = [string]$Script:CurrentIdentity.Account
                allowedCmdlets = $effectiveCmdlets
                cmdletsNeutralizedByDenial = $neutralizedCmdlets
                serviceTools = $serviceTools
                reachableVCenters = @(Get-AllowedVCenters -IPSource $Context.IPSource)
                applicableRules = @($applicable | Sort-Object { $_.Priority } | ForEach-Object { [ordered]@{ id = $_.Id; name = $_.Name; effect = $_.Effect; priority = $_.Priority } })
                quotas = $quotas
                objectsPerResponse = [ordered]@{ default = $g.DefaultBatchSize; max = $g.MaxBatchSize; note = "MIThrandir returns at most $($g.DefaultBatchSize) objects by default and $($g.MaxBatchSize) at most (Limit parameter)." }
                note = 'An applicable Deny always wins; reachable vCenters are the intersection of the scopes of the Allow rules.'
            }
        }
    })

    $examples = "Examples: Get-VM -Name 'TST-*' -Server vc-test | Select-Object Name, PowerState, NumCpu ; Get-Cluster CL-TEST | Get-VMHost | Get-Datastore | Where-Object FreeSpaceGB -lt 100 | Sort-Object FreeSpaceGB ; Get-VM TST-WEB01 | Get-Snapshot"
    $catalog.Add(@{
        Name = 'Invoke-PowerCLI'; Title = 'PowerCLI line'; Level = 'Read'
        Description = "Runs ONE PowerCLI line (pipeline accepted)$(if (-not (Get-Global).AllowWrite) { ' in read-only mode' }). Allowed cmdlets: $((Get-Global).AllowedCmdlets -join ', ') from the VMware modules, plus $((Get-Global).Utilities -join ', ') with simple expressions on `$_. No variables, assignments, loops, methods or [types]. -Server takes a short vCenter name (Get-VIServer); without -Server, all allowed vCenters are queried and each object carries its vCenter. Paged result. $examples"
        InputSchema = @{
            type = 'object'
            properties = [ordered]@{
                Line = @{ type = 'string'; description = 'The PowerCLI line to run, on a single line.' }
                Limit = @{ type = 'integer'; description = "Maximum objects returned (1 to $((Get-Global).MaxBatchSize), default $((Get-Global).DefaultBatchSize))."; minimum = 1; maximum = (Get-Global).MaxBatchSize }
            }
            required = @('Line'); additionalProperties = $false
        }
        Action = {
            param([hashtable]$Arguments, [hashtable]$Context)
            if (-not $Arguments.ContainsKey('Line') -or [string]::IsNullOrWhiteSpace([string]$Arguments['Line'])) { throw 'argument Line is mandatory' }
            return Invoke-PowercliLine -Line ([string]$Arguments['Line']).Trim() -Context $Context -Limit (Get-BatchSize -Arguments $Arguments)
        }
    })

    # Cached inventory (bulk reads without querying the vCenters)
    if ($Script:Inventory.active) { $catalog.Add((New-InventoryTool)) }

    # Typed tools generated from the installed cmdlets
    foreach ($cmdletName in @((Get-Global).TypedTools)) {
        $command = Get-SandboxCommand -Name $cmdletName
        if ($null -eq $command) { Write-Journal -Level 'ERROR' -Message "TypedTools: cmdlet not found, ignored: $cmdletName"; continue }
        $verdict = Test-AllowedCmdlet -Name $command.Name -Module ([string]$command.ModuleName) -IPSource 'default'
        if (-not $verdict.Ok -or $verdict.Type -ne 'PowerCLI') { Write-Journal -Level 'ERROR' -Message "TypedTools: $cmdletName not allowed by the policy, ignored"; continue }
        $catalog.Add((New-ToolType -Command $command))
    }
    Write-Journal -Level 'INFO' -Message 'Catalog built' -Data @{ tools = @($catalog.Name) }
    return $catalog
}
