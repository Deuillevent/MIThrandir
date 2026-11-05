<#
.SYNOPSIS
    MIThrandir V4 policy engine: global settings + rules (who, what, where, when, how much), versioned store,
    hot reload, suspensions, single use, simulator.

.DESCRIPTION
    Policy document (JSON in policies\active.json, versioned in policies\history\):
      Global           : cmdlet allow list (sandbox lock), utilities, excluded parameters and properties,
                         typed tools, limits. Anything not allowed here does not exist for anyone.
      CommandGroups : name -> list of cmdlets or patterns (read-inventory, read-storage, ...)
      Scopes       : name -> conditions (VCenters; Tags, Clusters, Folders, VmPatterns, InfraVisible: see Scope.ps1)
      Rules           : list ordered by Priority (priority). A rule =
                         Id, Name, Comment, Effect (Allow | Deny), Priority, State (active | inactive),
                         Subjects   { Agents (IP or *), Accounts, Groups }           (one is enough)
                         Commands{ Groups, Cmdlets (patterns), Tools (no-PowerCLI MCP tools or *) }
                         Scopes [names]                                          (union)
                         Validity { Start (start), End, Days [1-7, 1 = Monday], StartTime, EndTime, MaxUsage }
                         Limits   { CallQuotaPerHour }
    Runtime state (policies\state.json, not versioned): uses consumed per rule, suspended rules.

    Decision for a request (agent, cmdlets of the line, tool):
      1. gateway or agent suspended -> deny
      2. an applicable Deny rule (subject, validity) that covers the tool or one of the cmdlets -> deny, naming the rule
      3. each cmdlet must be covered by at least one applicable Allow rule; otherwise deny, naming the cmdlet
      4. allowed vCenters = intersection, over the cmdlets, of the union of the scopes of the rules covering them
      5. quota: each retained rule has its own per-agent counter; single use: consumed on successful execution
    Everything is computed BEFORE any PowerCLI command runs.
#>

$Script:Policy        = $null
$Script:PolicyMeta    = $null
$Script:PoliciesPath = $null
$Script:RulesState       = @{ usages = @{}; suspended = @{} }   # persisted in state.json
$Script:RuleCounters  = @{}   # "ruleId|ip" -> list of timestamps (sliding quota per rule and per agent)
$Script:AgentSandboxSeconds = @{}  # agent key -> list of @{ t = DateTime; s = seconds } (sliding 1 h sandbox time budget, V4.6)
$Script:GatewayState   = [ordered]@{ suspended = $false; reason = ''; by = ''; since = '' }
$Script:SuspendedAgents  = @{}
$Script:CommonParameters = @('Verbose', 'Debug', 'ErrorAction', 'WarningAction', 'InformationAction', 'ErrorVariable', 'WarningVariable',
    'InformationVariable', 'OutVariable', 'OutBuffer', 'PipelineVariable', 'ProgressAction', 'WhatIf', 'Confirm')
$Script:NonPowerCliTools = @('Get-MIThrandirTime', 'Get-VIServer', 'Get-MIThrandirCapabilities', 'Get-MIThrandirMyRights')
# V4.6: connection/session cmdlets managed by MIThrandir, denied whatever the allow list says (even '*')
$Script:AlwaysDeniedCmdlets = @('Connect-VIServer', 'Disconnect-VIServer', 'Connect-CisServer', 'Disconnect-CisServer', 'Set-PowerCLIConfiguration')

# ---------------------------------------------------------------------------
# Default (shipped) policy: groups, scopes, example rules
# ---------------------------------------------------------------------------
# Display and sorting flags for rules (no effect on evaluation: a Deny always wins)
$Script:RuleFlags = @('prioritized', 'critical', 'temporary', 'single-use', 'to-review')

# ----- V4.6: default values for the new global settings (also applied to earlier policies) -----
function Get-DefaultAllowedParameters {
    <# Exceptions to ExcludedParameters (excluded parameters), per cmdlet: Get-View -Id (MoRefs checked against Global.Views.Types). #>
    return @{ 'Get-View' = @('Id') }
}

function Get-DefaultMandatoryTargeting {
    <# Expensive cmdlets: the line must start with a targeted cmdlet (-Name, -Id, -Entity, -VM, -Location without a bare wildcard). #>
    return @('Get-Stat', 'Get-TagAssignment', 'Get-HardDisk', 'Get-NetworkAdapter', 'Get-ScsiLun')
}

function Get-DefaultViewRules {
    <#
    Get-View rules (V4.6).
      Types            : object types readable through -ViewType, -Id (MoRef "Type-value") and -SearchRoot.
      ForbiddenPaths : -Property paths and -Filter keys that are denied, along with their parents (requesting Config would return
                         Config.ExtraConfig). They are also stripped from the returned views (defense in depth).
      MaxProperties    : maximum number of paths per -Property.
      MandatoryProperty : -Property is required (a full view weighs hundreds of KB per VM).
    #>
    return @{
        Types = @('VirtualMachine', 'HostSystem', 'ClusterComputeResource', 'ComputeResource', 'Datastore', 'StoragePod', 'Folder', 'Datacenter',
                  'ResourcePool', 'VirtualApp', 'Network', 'DistributedVirtualPortgroup', 'VmwareDistributedVirtualSwitch', 'DistributedVirtualSwitch', 'OpaqueNetwork')
        # Notes (Annotation), ExtraConfig (guestinfo.*), OVF properties (VAppConfig), custom attributes (CustomValue, Value,
        # AvailableField), host advanced options (Config.Option)
        ForbiddenPaths = @('Config.Annotation', 'Summary.Config.Annotation', 'Config.ExtraConfig', 'Config.VAppConfig',
                             'CustomValue', 'Summary.CustomValue', 'Value', 'AvailableField', 'Config.Option')
        MaxProperties = 40
        MandatoryProperty = $true
    }
}

function New-DefaultPolicy {
    param([hashtable]$OldGlobal = $null)
    $global = if ($OldGlobal) { $OldGlobal } else {
        @{
            AllowedCmdlets = @('Get-*')
            # V4.6: Get-View is no longer excluded (it has its own rules: Global.Views); Get-Annotation, Get-CustomAttribute and
            # Get-AdvancedSetting are (custom attributes and ExtraConfig / guestinfo.* of VMs).
            ExcludedCmdlets    = @('Get-EsxCli', 'Get-VICredentialStoreItem', 'Get-VMHostAccount', 'Get-VMGuestNetworkInterface', 'Get-ErrorReport', 'Get-VIEvent', 'Get-Log', 'Get-LogType', 'Get-Annotation', 'Get-CustomAttribute', 'Get-AdvancedSetting')
            Utilities       = @('Where-Object', 'Select-Object', 'Sort-Object', 'Group-Object', 'Measure-Object')
            ExcludedParameters  = @('Id', 'RelatedObject', 'Tag', 'NoRecursion')
            ExcludedParametersPerCmdlet = @{}
            AllowedParametersPerCmdlet = (Get-DefaultAllowedParameters)
            ExcludedProperties = @('Notes', 'Description', 'CustomFields', 'ExtensionData', 'Client', 'Uid', 'Password')
            TypedTools       = @('Get-VM', 'Get-VMHost', 'Get-Cluster', 'Get-Datastore', 'Get-Snapshot', 'Get-Folder', 'Get-ResourcePool', 'Get-Datacenter')
            MaxBatchSize = 50; DefaultBatchSize = 25; MaxOutputSize = 20000; MaxDelaySeconds = 120
            DefaultCallQuotaPerHour = 120
            # V4.6: read-only by default. $true = the allow list may contain more than Get-* (write cmdlets),
            # to test rule blocking on a test environment. Connection cmdlets always remain denied.
            AllowWrite = $false
            SandboxSecondsPerHour = 900
            MandatoryTargeting = (Get-DefaultMandatoryTargeting)
            Views = (Get-DefaultViewRules)
        }
    }
    $inOneWeek = (Get-Date).Date.AddDays(7)
    return @{
        Global = $global
        CommandGroups = @{
            'diagnostic-mithrandir'  = @{ Description = 'MIThrandir connectivity and discovery tools, with no access to vSphere objects'; Cmdlets = @('Get-MIThrandirTime', 'Get-VIServer', 'Get-MIThrandirCapabilities', 'Get-MIThrandirMyRights') }
            'read-inventory'  = @{ Description = 'Inventory: VMs, hosts, clusters, folders, pools, datacenters, snapshots'; Cmdlets = @('Get-VM', 'Get-VMHost', 'Get-Cluster', 'Get-Datacenter', 'Get-Folder', 'Get-ResourcePool', 'Get-Snapshot', 'Get-VMGuest', 'Get-VApp', 'Get-Template') }
            'read-storage'    = @{ Description = 'Datastores, datastore clusters, virtual disks, LUNs'; Cmdlets = @('Get-Datastore', 'Get-DatastoreCluster', 'Get-HardDisk', 'Get-ScsiLun', 'Get-VMHostStorage', 'Get-VMHostHba') }
            'read-network'      = @{ Description = 'Switches, port groups, network adapters'; Cmdlets = @('Get-VirtualSwitch', 'Get-VirtualPortGroup', 'Get-VMHostNetworkAdapter', 'Get-NetworkAdapter', 'Get-VDSwitch', 'Get-VDPortgroup', 'Get-VMHostNetwork') }
            'read-performance' = @{ Description = 'Performance statistics (potentially large)'; Cmdlets = @('Get-Stat', 'Get-StatType', 'Get-StatInterval') }
            'read-configuration-host' = @{ Description = 'Host configuration: services, firewall, NTP, profiles, modules'; Cmdlets = @('Get-VMHostService', 'Get-VMHostFirewallException', 'Get-VMHostNtpServer', 'Get-VMHostProfile', 'Get-VMHostAdvancedConfiguration', 'Get-VMHostHardware', 'Get-VMHostPatch') }
            'read-views'        = @{ Description = 'Get-View: fast read of the vSphere API, -Property mandatory, object types and paths filtered (Global.Views)'; Cmdlets = @('Get-View') }
            'all-read'       = @{ Description = 'All Get-* cmdlets that the global allow list permits'; Cmdlets = @('Get-*') }
        }
        Scopes = @{
            'all-vcenters' = @{ Description = 'All vCenters declared in the configuration'; VCenters = @('*') }
        }
        Rules = @(
            @{
                Id = 'diagnostic'; Name = 'MIThrandir diagnostics for everyone'; Priority = 10; Effect = 'Allow'; State = 'active'; Flags = @('prioritized')
                Comment = 'Lets any agent check connectivity and list its vCenters. Keep this rule.'
                Subjects = @{ Agents = @('*'); Accounts = @(); Groups = @() }
                Commands = @{ Groups = @('diagnostic-mithrandir'); Cmdlets = @(); Tools = @() }
                Scopes = @('all-vcenters')
                Validity = @{ Start = $null; End = $null; Days = @(); StartTime = $null; EndTime = $null; MaxUsage = $null }
                Limits = @{ CallQuotaPerHour = 600 }
            }
            @{
                Id = 'read-poc'; Name = 'Read inventory and storage for everyone (POC)'; Priority = 100; Effect = 'Allow'; State = 'active'; Flags = @('to-review')
                Comment = 'Broad POC rule: any agent reads the inventory and storage of all vCenters. Restrict per agent before going to production.'
                Subjects = @{ Agents = @('*'); Accounts = @(); Groups = @() }
                Commands = @{ Groups = @('read-inventory', 'read-storage', 'read-network', 'read-configuration-host', 'read-views'); Cmdlets = @(); Tools = @() }
                Scopes = @('all-vcenters')
                Validity = @{ Start = $null; End = $null; Days = @(); StartTime = $null; EndTime = $null; MaxUsage = $null }
                Limits = @{ CallQuotaPerHour = 120 }
            }
            @{
                Id = 'perf-forbidden'; Name = 'Performance data forbidden outside business hours'; Priority = 20; Effect = 'Deny'; State = 'inactive'; Flags = @('critical')
                Comment = 'Example Deny rule with a time window: Get-Stat is denied outside 08:00-18:00 on business days. Enable it to try it.'
                Subjects = @{ Agents = @('*'); Accounts = @(); Groups = @() }
                Commands = @{ Groups = @('read-performance'); Cmdlets = @(); Tools = @() }
                Scopes = @()
                Validity = @{ Start = $null; End = $null; Days = @(1, 2, 3, 4, 5); StartTime = '18:00'; EndTime = '08:00'; MaxUsage = $null }
                Limits = @{ CallQuotaPerHour = 0 }
            }
            @{
                Id = 'access-oneOff-example'; Name = 'One-off access (example: a single execution, one week)'; Priority = 50; Effect = 'Allow'; State = 'inactive'; Flags = @('temporary', 'single-use')
                Comment = 'Temporary access template: one specific agent, all read, valid 7 days, a single execution, then the rule becomes exhausted. Duplicate and adapt.'
                Subjects = @{ Agents = @('10.0.0.1'); Accounts = @(); Groups = @() }
                Commands = @{ Groups = @('all-read'); Cmdlets = @(); Tools = @() }
                Scopes = @('all-vcenters')
                Validity = @{ Start = (Get-Date).Date.ToString('o'); End = $inOneWeek.ToString('o'); Days = @(); StartTime = $null; EndTime = $null; MaxUsage = 1 }
                Limits = @{ CallQuotaPerHour = 10 }
            }
        )
    }
}

# ---------------------------------------------------------------------------
# Normalization and consistency
# ---------------------------------------------------------------------------
function ConvertTo-DeepHashtable {
    param($Object)
    if ($Object -is [System.Collections.IDictionary]) {
        $h = @{}
        foreach ($key in $Object.Keys) { $h[$key] = ConvertTo-DeepHashtable -Object $Object[$key] }
        return $h
    }
    if ($Object -is [System.Collections.IList] -and $Object -isnot [string]) { return @($Object | ForEach-Object { ConvertTo-DeepHashtable -Object $_ }) }
    return $Object
}

function ConvertTo-DateTime {
    <# Accepts a DateTime (as produced by ConvertFrom-Json) or an ISO 8601 / locale string. $null if empty. #>
    param($Value)
    if ($null -eq $Value -or ([string]$Value).Trim() -eq '') { return $null }
    if ($Value -is [datetime]) { return $Value }
    if ($Value -is [DateTimeOffset]) { return $Value.LocalDateTime }
    $text = ([string]$Value).Trim()
    $result = [datetime]::MinValue
    if ([datetime]::TryParse($text, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind, [ref]$result)) { return $result }
    if ([datetime]::TryParse($text, [cultureinfo]::CurrentCulture, [System.Globalization.DateTimeStyles]::AssumeLocal, [ref]$result)) { return $result }
    throw "invalid date: $text"
}

function ConvertTo-TextList {
    param($Value)
    if ($null -eq $Value) { return @() }
    if ($Value -is [string]) { return @($Value -split '[,;\r\n]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
    return @($Value | ForEach-Object { [string]$_ } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function Test-PolicyConsistency {
    <# Returns the normalized policy or throws an explicit exception. No state is modified. #>
    param([Parameter(Mandatory)][hashtable]$Policy)
    $p = ConvertTo-DeepHashtable -Object $Policy
    if (-not $p.ContainsKey('Global')) { throw "Global section missing" }
    $g = $p.Global
    foreach ($key in @('AllowedCmdlets', 'Utilities', 'MaxBatchSize', 'DefaultBatchSize', 'TypedTools')) { if (-not $g.ContainsKey($key)) { throw "Global.$key missing" } }
    foreach ($key in @('ExcludedCmdlets', 'ExcludedParameters', 'ExcludedProperties')) { if (-not $g.ContainsKey($key)) { $g[$key] = @() } }
    if (-not $g.ContainsKey('ExcludedParametersPerCmdlet')) { $g.ExcludedParametersPerCmdlet = @{} }
    if (-not $g.ContainsKey('MaxOutputSize'))  { $g.MaxOutputSize = 60000 }
    if (-not $g.ContainsKey('MaxDelaySeconds')) { $g.MaxDelaySeconds = 120 }
    if (-not $g.ContainsKey('DefaultCallQuotaPerHour')) { $g.DefaultCallQuotaPerHour = 120 }
    # V4.6: new settings, default values for earlier policies (Get-View stays excluded as long as it is listed in ExcludedCmdlets)
    if (-not $g.ContainsKey('AllowedParametersPerCmdlet') -or $g.AllowedParametersPerCmdlet -isnot [hashtable]) { $g.AllowedParametersPerCmdlet = Get-DefaultAllowedParameters }
    foreach ($cmd in @($g.AllowedParametersPerCmdlet.Keys)) { $g.AllowedParametersPerCmdlet[$cmd] = @(ConvertTo-TextList $g.AllowedParametersPerCmdlet[$cmd]) }
    if (-not $g.ContainsKey('SandboxSecondsPerHour')) { $g.SandboxSecondsPerHour = 900 }
    if (-not $g.ContainsKey('MandatoryTargeting')) { $g.MandatoryTargeting = Get-DefaultMandatoryTargeting }
    $g.MandatoryTargeting = @(ConvertTo-TextList $g.MandatoryTargeting)
    $defaultViews = Get-DefaultViewRules
    if (-not $g.ContainsKey('Views') -or $g.Views -isnot [hashtable]) { $g.Views = $defaultViews }
    foreach ($key in @($defaultViews.Keys)) { if (-not $g.Views.ContainsKey($key)) { $g.Views[$key] = $defaultViews[$key] } }
    $g.Views.Types = @(ConvertTo-TextList $g.Views.Types)
    $g.Views.ForbiddenPaths = @(ConvertTo-TextList $g.Views.ForbiddenPaths)
    foreach ($t in $g.Views.Types) { if ($t -notmatch '^[A-Za-z]+$') { throw "Global.Views.Types: invalid type: $t" } }
    foreach ($c in $g.Views.ForbiddenPaths) { if ($c -notmatch '^[A-Za-z][A-Za-z0-9]*(\.[A-Za-z][A-Za-z0-9]*)*$') { throw "Global.Views.ForbiddenPaths: invalid path: $c" } }
    try { $g.Views.MaxProperties = [int]$g.Views.MaxProperties } catch { throw 'Global.Views.MaxProperties must be a number' }
    if ($g.Views.MaxProperties -lt 1 -or $g.Views.MaxProperties -gt 200) { throw 'Global.Views.MaxProperties: between 1 and 200' }
    $g.Views.MandatoryProperty = [bool]$g.Views.MandatoryProperty
    foreach ($key in @('AllowedCmdlets', 'ExcludedCmdlets', 'Utilities', 'ExcludedParameters', 'ExcludedProperties', 'TypedTools')) { $g[$key] = @(ConvertTo-TextList $g[$key]) }
    $g.Utilities = @($g.Utilities | Select-Object -Unique)
    foreach ($key in @('MaxBatchSize', 'DefaultBatchSize', 'MaxOutputSize', 'MaxDelaySeconds', 'DefaultCallQuotaPerHour', 'SandboxSecondsPerHour')) {
        try { $g[$key] = [int]$g[$key] } catch { throw "Global.$key must be a number" }
    }
    if ($g.SandboxSecondsPerHour -lt 0) { throw 'Global.SandboxSecondsPerHour: 0 (no limit) or a positive number' }
    if ($g.MaxOutputSize -lt 2000) { throw 'Global.MaxOutputSize: 2000 characters minimum' }
    if ($g.DefaultBatchSize -gt $g.MaxBatchSize) { throw 'Global.DefaultBatchSize cannot exceed MaxBatchSize' }
    if ($g.AllowedCmdlets.Count -eq 0) { throw 'Global.AllowedCmdlets cannot be empty' }
    if ($g.ContainsKey('Sentinel') -and $null -ne $g.Sentinel) {
        if ($g.Sentinel -isnot [hashtable]) { throw 'Global.Sentinel: invalid format' }
        if (Get-Command -Name Test-SentinelConfig -ErrorAction SilentlyContinue) { $g.Sentinel = Test-SentinelConfig -Value $g.Sentinel }
    }
    # V4.6: read-only by default. AllowWrite = $true lifts the Get-* restriction (to test rule blocking
    # with write commands, typically on a service account that is read-only on the vCenter side).
    $g.AllowWrite = [bool]$(if ($g.ContainsKey('AllowWrite')) { $g.AllowWrite } else { $false })
    if (-not $g.AllowWrite) {
        foreach ($pattern in $g.AllowedCmdlets) { if ($pattern -notlike 'Get-*') { throw "Global.AllowedCmdlets: only Get-* patterns are accepted while Global.AllowWrite = `$false (found: $pattern)" } }
    }
    else {
        foreach ($pattern in $g.AllowedCmdlets) { if ($pattern -ne '*' -and $pattern -notmatch '^[A-Za-z][A-Za-z0-9]*-[A-Za-z0-9*?]+$') { throw "Global.AllowedCmdlets: invalid cmdlet pattern: $pattern (e.g. '*', 'Get-*', 'Set-VM*')" } }
    }

    if (-not $p.ContainsKey('CommandGroups')) { $p.CommandGroups = @{} }
    foreach ($name in @($p.CommandGroups.Keys)) {
        if ($name -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$') { throw "invalid command group name: $name" }
        $grp = $p.CommandGroups[$name]
        if ($grp -isnot [hashtable]) { $grp = @{ Cmdlets = $grp } }
        $grp.Cmdlets = @(ConvertTo-TextList $grp.Cmdlets)
        if (-not $grp.ContainsKey('Description')) { $grp.Description = '' }
        if ($grp.Cmdlets.Count -eq 0) { throw "command group $name has no cmdlet" }
        $p.CommandGroups[$name] = $grp
    }
    # Backward compatibility: the discovery tools (V4.7) join the existing diagnostic-mithrandir group if missing from it,
    # so that an earlier policy exposes them to every agent already covered by that group.
    if ($p.CommandGroups.ContainsKey('diagnostic-mithrandir')) {
        $diag = $p.CommandGroups['diagnostic-mithrandir']
        foreach ($tool in @('Get-MIThrandirCapabilities', 'Get-MIThrandirMyRights')) {
            if ($tool -notin $diag.Cmdlets) { $diag.Cmdlets = @($diag.Cmdlets) + $tool }
        }
    }
    if (-not $p.ContainsKey('Scopes')) { $p.Scopes = @{} }
    foreach ($name in @($p.Scopes.Keys)) {
        if ($name -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$') { throw "invalid scope name: $name" }
        $per = $p.Scopes[$name]
        if ($per -isnot [hashtable]) { throw "scope '$name': invalid format" }
        foreach ($key in @('VCenters', 'Tags', 'Clusters', 'Folders', 'VmPatterns')) { $per[$key] = @(ConvertTo-TextList $(if ($per.ContainsKey($key)) { $per[$key] } else { $null })) }
        if (-not $per.ContainsKey('Description')) { $per.Description = '' }
        $per.InfraVisible = [bool]$(if ($per.ContainsKey('InfraVisible')) { $per.InfraVisible } else { $false })
        foreach ($key in @('Clusters', 'Folders', 'VmPatterns', 'Tags')) {
            foreach ($pattern in $per[$key]) { if ($pattern.StartsWith('^')) { try { [void][regex]::new($pattern) } catch { throw "scope '$name': invalid regular expression in '$key': $pattern" } } }
        }
        if ($per.VCenters.Count -eq 0) { throw "scope '$name': at least one vCenter (or *) is required in this version" }
    }

    if (-not $p.ContainsKey('Rules')) { $p.Rules = @() }
    $p.Rules = @($p.Rules)
    $ids = @{}
    foreach ($r in $p.Rules) {
        if ($r -isnot [hashtable]) { throw 'rule: invalid format' }
        foreach ($key in @('Id', 'Name', 'Effect')) { if (-not $r.ContainsKey($key) -or [string]::IsNullOrWhiteSpace([string]$r[$key])) { throw "rule: field $key is mandatory" } }
        $r.Id = ([string]$r.Id).Trim()
        if ($r.Id -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$') { throw "rule: invalid identifier: $($r.Id)" }
        if ($ids.ContainsKey($r.Id)) { throw "rule: duplicate identifier: $($r.Id)" }
        $ids[$r.Id] = $true
        if ($r.Effect -notin @('Allow', 'Deny')) { throw "rule $($r.Id): Effect must be Allow or Deny" }
        if (-not $r.ContainsKey('State') -or $r.State -notin @('active', 'inactive')) { $r.State = 'inactive' }
        if (-not $r.ContainsKey('Priority')) { $r.Priority = 100 }
        $r.Priority = [int]$r.Priority
        if (-not $r.ContainsKey('Comment')) { $r.Comment = '' }
        $r.Flags = @(ConvertTo-TextList $(if ($r.ContainsKey('Flags')) { $r.Flags } else { $null }) | ForEach-Object { $_.ToLowerInvariant() } | Select-Object -Unique)
        foreach ($flag in $r.Flags) { if ($flag -notin $Script:RuleFlags) { throw "rule $($r.Id): unknown flag: $flag (values: $($Script:RuleFlags -join ', '))" } }
        if (-not $r.ContainsKey('Subjects') -or $r.Subjects -isnot [hashtable]) { $r.Subjects = @{} }
        foreach ($key in @('Agents', 'Accounts', 'Groups')) { $r.Subjects[$key] = @(ConvertTo-TextList $(if ($r.Subjects.ContainsKey($key)) { $r.Subjects[$key] } else { $null })) }
        if (($r.Subjects.Agents.Count + $r.Subjects.Accounts.Count + $r.Subjects.Groups.Count) -eq 0) { throw "rule $($r.Id): at least one subject (agent, account or group)" }
        if (-not $r.ContainsKey('Commands') -or $r.Commands -isnot [hashtable]) { $r.Commands = @{} }
        foreach ($key in @('Groups', 'Cmdlets', 'Tools')) { $r.Commands[$key] = @(ConvertTo-TextList $(if ($r.Commands.ContainsKey($key)) { $r.Commands[$key] } else { $null })) }
        foreach ($grp in $r.Commands.Groups) { if (-not $p.CommandGroups.ContainsKey($grp)) { throw "rule $($r.Id): unknown command group: $grp" } }
        if (($r.Commands.Groups.Count + $r.Commands.Cmdlets.Count + $r.Commands.Tools.Count) -eq 0) { throw "rule $($r.Id): at least one group, cmdlet or tool" }
        $r.Scopes = @(ConvertTo-TextList $(if ($r.ContainsKey('Scopes')) { $r.Scopes } else { $null }))
        foreach ($per in $r.Scopes) { if (-not $p.Scopes.ContainsKey($per) -and $per -notlike 'vc:*') { throw "rule $($r.Id): unknown scope: $per" } }
        if ($r.Effect -eq 'Allow' -and $r.Scopes.Count -eq 0) { throw "rule $($r.Id): an Allow rule must have at least one scope" }
        if (-not $r.ContainsKey('Validity') -or $r.Validity -isnot [hashtable]) { $r.Validity = @{} }
        $v = $r.Validity
        foreach ($key in @('Start', 'End')) {
            $d = $null
            try { $d = ConvertTo-DateTime $(if ($v.ContainsKey($key)) { $v[$key] } else { $null }) } catch { throw "rule $($r.Id): Validity.$key is not a valid date" }
            $v[$key] = if ($null -eq $d) { $null } else { $d.ToString('o') }
        }
        if ($v.Start -and $v.End -and ([datetime]$v.Start) -gt ([datetime]$v.End)) { throw "rule $($r.Id): Validity.Start is after Validity.End" }
        $v.Days = @(ConvertTo-TextList $(if ($v.ContainsKey('Days')) { $v.Days } else { $null }) | ForEach-Object { [int]$_ })
        foreach ($j in $v.Days) { if ($j -lt 1 -or $j -gt 7) { throw "rule $($r.Id): Validity.Days must contain values from 1 (Monday) to 7 (Sunday)" } }
        foreach ($key in @('StartTime', 'EndTime')) {
            if (-not $v.ContainsKey($key) -or [string]::IsNullOrWhiteSpace([string]$v[$key])) { $v[$key] = $null }
            else { try { $v[$key] = ([TimeSpan]::Parse([string]$v[$key])).ToString('hh\:mm') } catch { throw "rule $($r.Id): Validity.$key must be a time HH:mm" } }
        }
        if (($v.StartTime -and -not $v.EndTime) -or ($v.EndTime -and -not $v.StartTime)) { throw "rule $($r.Id): StartTime and EndTime go together" }
        if (-not $v.ContainsKey('MaxUsage') -or $null -eq $v.MaxUsage -or [string]$v.MaxUsage -eq '') { $v.MaxUsage = $null } else { $v.MaxUsage = [int]$v.MaxUsage; if ($v.MaxUsage -lt 1) { $v.MaxUsage = $null } }
        if (-not $r.ContainsKey('Limits') -or $r.Limits -isnot [hashtable]) { $r.Limits = @{} }
        if (-not $r.Limits.ContainsKey('CallQuotaPerHour') -or $null -eq $r.Limits.CallQuotaPerHour -or [string]$r.Limits.CallQuotaPerHour -eq '') { $r.Limits.CallQuotaPerHour = $g.DefaultCallQuotaPerHour } else { $r.Limits.CallQuotaPerHour = [int]$r.Limits.CallQuotaPerHour }
    }
    $p.Rules = @($p.Rules | Sort-Object { $_.Priority }, { $_.Id })
    return $p
}

# ---------------------------------------------------------------------------
# Store: versions, state, loading, hot apply
# ---------------------------------------------------------------------------
function Get-PolicyVersions {
    $folder = Join-Path $Script:PoliciesPath 'history'
    if (-not (Test-Path $folder)) { return @() }
    return @(Get-ChildItem -Path $folder -Filter '*.json' | Sort-Object Name -Descending | ForEach-Object {
        try { $m = (Get-Content -Path $_.FullName -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable -Depth 20).meta; [ordered]@{ version = $m.version; author = $m.author; date = $m.date; comment = $m.comment; sha256 = $m.sha256; file = $_.Name } }
        catch { [ordered]@{ version = 0; author = '?'; date = ''; comment = "unreadable: $($_.Exception.Message)"; sha256 = ''; file = $_.Name } }
    })
}

function Read-PolicyFile {
    param([string]$Path)
    $document = Get-Content -Path $Path -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable -Depth 20
    if (-not $document.ContainsKey('policy')) { throw "file '$Path': key 'policy' missing" }
    return @{ Meta = (ConvertTo-DeepHashtable -Object $document.meta); Policy = (ConvertTo-DeepHashtable -Object $document.policy) }
}

function Save-PolicyVersion {
    param([Parameter(Mandatory)][hashtable]$Policy, [Parameter(Mandatory)][string]$Author, [string]$Comment = '')
    $normalized = Test-PolicyConsistency -Policy $Policy
    $versions = @(Get-PolicyVersions)
    $number = if ($versions.Count -gt 0) { ([int](($versions | ForEach-Object { $_.version }) | Measure-Object -Maximum).Maximum) + 1 } else { 1 }
    $json = $normalized | ConvertTo-Json -Depth 12
    $sha = [BitConverter]::ToString([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($json))).Replace('-', '')
    $meta = [ordered]@{ version = $number; author = $Author; date = (Get-Date).ToString('o'); comment = $Comment; sha256 = $sha }
    $document = [ordered]@{ meta = $meta; policy = $normalized } | ConvertTo-Json -Depth 12
    $historyFolder = Join-Path $Script:PoliciesPath 'history'
    if (-not (Test-Path $historyFolder)) { New-Item -ItemType Directory -Path $historyFolder -Force | Out-Null }
    $utf8 = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText((Join-Path $historyFolder ("v{0:D5}.json" -f $number)), $document, $utf8)
    [System.IO.File]::WriteAllText((Join-Path $Script:PoliciesPath 'active.json'), $document, $utf8)
    Set-ActivePolicy -Policy $normalized -Meta $meta
    return $meta
}

function Save-RulesState {
    try {
        $utf8 = [System.Text.UTF8Encoding]::new($false)
        [System.IO.File]::WriteAllText((Join-Path $Script:PoliciesPath 'state.json'), ($Script:RulesState | ConvertTo-Json -Depth 6), $utf8)
    } catch { Write-Journal -Level 'ERROR' -Message "Cannot write state.json: $($_.Exception.Message)" }
}

function Read-RulesState {
    $path = Join-Path $Script:PoliciesPath 'state.json'
    if (Test-Path $path) {
        try {
            $lu = ConvertTo-DeepHashtable -Object (Get-Content -Path $path -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable -Depth 6)
            if (-not $lu.ContainsKey('usages')) { $lu.usages = @{} }
            if (-not $lu.ContainsKey('suspended')) { $lu.suspended = @{} }
            $Script:RulesState = $lu
        } catch { Write-Journal -Level 'ERROR' -Message "state.json unreadable, reset: $($_.Exception.Message)" }
    }
}

function Set-ActivePolicy {
    param([hashtable]$Policy, [hashtable]$Meta)
    $Script:Policy = $Policy
    $Script:PolicyMeta = $Meta
    $Script:RuleCounters = @{}
    if (Get-Variable -Name Sandbox -Scope Script -ErrorAction SilentlyContinue) {
        if ($Script:Sandbox -and $Script:Sandbox.Locked) { Lock-Sandbox }
    }
    if (Get-Command -Name Get-ToolCatalog -ErrorAction SilentlyContinue) {
        if (Get-Variable -Name Catalog -Scope Script -ErrorAction SilentlyContinue) {
            $with = [bool](Get-Variable -Name WithActiveVCenter -Scope Script -ValueOnly -ErrorAction SilentlyContinue)
            $Script:Catalog = Get-ToolCatalog -WithVCenter:$with
        }
    }
    Write-Journal -Level 'INFO' -Message 'Policy active' -Data @{
        version = $Meta.version; author = $Meta.author; sha256 = $Meta.sha256; comment = $Meta.comment
        cmdlets = $Policy.Global.AllowedCmdlets; excluded = $Policy.Global.ExcludedCmdlets
        rules = @($Policy.Rules | ForEach-Object { "$($_.Id):$($_.State)" }); groups = @($Policy.CommandGroups.Keys); scopes = @($Policy.Scopes.Keys)
    }
}

function Initialize-Policy {
    <# Loads policies\active.json; otherwise creates the default policy (reusing the global settings of a V3 Policy.psd1 if one exists). #>
    param([Parameter(Mandatory)][string]$RepositoryPath, [string]$Psd1Path = '')
    $Script:PoliciesPath = $RepositoryPath
    if (-not (Test-Path $RepositoryPath)) { New-Item -ItemType Directory -Path $RepositoryPath -Force | Out-Null }
    Read-RulesState
    $active = Join-Path $RepositoryPath 'active.json'
    if (Test-Path $active) {
        $lu = Read-PolicyFile -Path $active
        if (-not $lu.Policy.ContainsKey('Global')) {
            # V3 document (flat): migrate to the V4 format with the default rules
            Write-Journal -Level 'ADMIN' -Message 'Migrating the V3 policy to the V4 format (rules)' -Data @{ author = "$env:USERDOMAIN\$env:USERNAME" }
            $globalSettings = @{}
            foreach ($key in @('AllowedCmdlets', 'ExcludedCmdlets', 'Utilities', 'ExcludedParameters', 'ExcludedParametersPerCmdlet', 'ExcludedProperties', 'TypedTools', 'MaxBatchSize', 'DefaultBatchSize', 'MaxOutputSize', 'MaxDelaySeconds')) { if ($lu.Policy.ContainsKey($key)) { $globalSettings[$key] = $lu.Policy[$key] } }
            if ($lu.Policy.ContainsKey('CallQuotaPerHour')) { $globalSettings.DefaultCallQuotaPerHour = $lu.Policy.CallQuotaPerHour }
            [void](Save-PolicyVersion -Policy (New-DefaultPolicy -OldGlobal $globalSettings) -Author "$env:USERDOMAIN\$env:USERNAME" -Comment 'Migration V3 to V4: global settings kept, default rules added')
            return
        }
        Set-ActivePolicy -Policy (Test-PolicyConsistency -Policy $lu.Policy) -Meta $lu.Meta
        return
    }
    $globalSettings = $null
    if ($Psd1Path -and (Test-Path $Psd1Path)) {
        $old = Import-PowerShellDataFile -Path $Psd1Path
        $globalSettings = @{}
        foreach ($key in @('AllowedCmdlets', 'ExcludedCmdlets', 'Utilities', 'ExcludedParameters', 'ExcludedParametersPerCmdlet', 'ExcludedProperties', 'TypedTools', 'MaxBatchSize', 'DefaultBatchSize', 'MaxOutputSize', 'MaxDelaySeconds')) { if ($old.ContainsKey($key)) { $globalSettings[$key] = $old[$key] } }
        if ($old.ContainsKey('CallQuotaPerHour')) { $globalSettings.DefaultCallQuotaPerHour = $old.CallQuotaPerHour }
    }
    Write-Journal -Level 'ADMIN' -Message 'Creating the default policy' -Data @{ author = "$env:USERDOMAIN\$env:USERNAME"; depot = $RepositoryPath; fromPsd1 = [bool]$globalSettings }
    [void](Save-PolicyVersion -Policy (New-DefaultPolicy -OldGlobal $globalSettings) -Author "$env:USERDOMAIN\$env:USERNAME" -Comment 'Default policy shipped with MIThrandir')
}

function Restore-PolicyVersion {
    param([Parameter(Mandatory)][int]$Version, [Parameter(Mandatory)][string]$Author)
    $file = Join-Path (Join-Path $Script:PoliciesPath 'history') ("v{0:D5}.json" -f $Version)
    if (-not (Test-Path $file)) { throw "version $Version not found" }
    $lu = Read-PolicyFile -Path $file
    return (Save-PolicyVersion -Policy $lu.Policy -Author $Author -Comment "Restore of version $Version")
}

# ---------------------------------------------------------------------------
# Accessors used by the rest of MIThrandir (global allow list)
# ---------------------------------------------------------------------------
function Get-Global { return $Script:Policy.Global }

function Test-PatternList {
    param([string]$Value, [array]$Patterns)
    foreach ($pattern in $Patterns) { if ($Value -like $pattern) { return $true } }
    return $false
}

function Test-AllowedCmdlet {
    <# GLOBAL allow list (what the sandbox leaves visible). Per-agent rights come from the rules (Resolve-Decision). #>
    param([string]$Name, [string]$Module, [string]$IPSource = '')
    $g = Get-Global
    if ($Name -in $g.Utilities) { return @{ Ok = $true; Type = 'Utility' } }
    if ($Module -notlike 'VMware.*') { return @{ Ok = $false; Reason = "command outside PowerCLI: $Name" } }
    # V4.6: connection/session cmdlets are managed by MIThrandir and ALWAYS denied, even with a '*' allow list
    # (otherwise an agent could open its own vCenter sessions or reconfigure PowerCLI inside the sandbox).
    if ($Name -in $Script:AlwaysDeniedCmdlets) { return @{ Ok = $false; Reason = "cmdlet reserved for MIThrandir (always denied): $Name" } }
    if (-not (Test-PatternList -Value $Name -Patterns $g.AllowedCmdlets)) { return @{ Ok = $false; Reason = "cmdlet not allowed: $Name" } }
    if ($Name -in $g.ExcludedCmdlets) { return @{ Ok = $false; Reason = "cmdlet excluded by the policy: $Name" } }
    return @{ Ok = $true; Type = 'PowerCLI' }
}

function Test-AllowedParameter {
    param([string]$Cmdlet, [string]$Parameter)
    $g = Get-Global
    # V4.6: in write mode, -WhatIf and -Confirm are permitted (dry runs and no-interactive execution of write cmdlets)
    $allowedCommon = if ($g.AllowWrite) { @('ErrorAction', 'WhatIf', 'Confirm') } else { @('ErrorAction') }
    if ($Parameter -in $Script:CommonParameters -and $Parameter -notin $allowedCommon) { return $false }
    $byCmdlet = $g.ExcludedParametersPerCmdlet
    if ($byCmdlet.ContainsKey($Cmdlet) -and $Parameter -in @($byCmdlet[$Cmdlet])) { return $false }
    # V4.6: explicit exception to the global list (e.g. Get-View -Id, checked by Global.Views)
    $exceptions = if ($g.ContainsKey('AllowedParametersPerCmdlet')) { $g.AllowedParametersPerCmdlet } else { @{} }
    if ($exceptions.ContainsKey($Cmdlet) -and $Parameter -in @($exceptions[$Cmdlet])) { return $true }
    if ($Parameter -in $g.ExcludedParameters) { return $false }
    return $true
}

function Test-SandboxSecondsBudget {
    <# V4.6: per-agent sandbox time budget, sliding over one hour (Global.SandboxSecondsPerHour; 0 = no limit).
       Bounds the load of a single agent regardless of the number of calls. #>
    param([Parameter(Mandatory)][string]$Key)
    $budget = [int](Get-Global).SandboxSecondsPerHour
    if ($budget -le 0) { return @{ Ok = $true } }
    $limit = (Get-Date).AddHours(-1)
    $list = @(if ($Script:AgentSandboxSeconds.ContainsKey($Key)) { $Script:AgentSandboxSeconds[$Key] | Where-Object { [datetime]$_.t -gt $limit } } else { @() })
    $Script:AgentSandboxSeconds[$Key] = $list
    $consumed = ($list | ForEach-Object { [double]$_.s } | Measure-Object -Sum).Sum
    if ($consumed -ge $budget) { return @{ Ok = $false; Reason = "compute time budget exhausted ($([int]$consumed) s of $budget s over the last hour): wait or target the request more narrowly" } }
    return @{ Ok = $true }
}

function Add-SandboxSeconds {
    param([Parameter(Mandatory)][string]$Key, [double]$Seconds)
    if ([int](Get-Global).SandboxSecondsPerHour -le 0) { return }
    if (-not $Script:AgentSandboxSeconds.ContainsKey($Key)) { $Script:AgentSandboxSeconds[$Key] = @() }
    $Script:AgentSandboxSeconds[$Key] = @($Script:AgentSandboxSeconds[$Key]) + @(@{ t = (Get-Date); s = [double]$Seconds })
}

function Get-BatchSize {
    param([hashtable]$Arguments, [string]$ParameterName = 'Limit')
    $g = Get-Global
    $default = [int]$g.DefaultBatchSize; $max = [int]$g.MaxBatchSize
    if (-not $Arguments.ContainsKey($ParameterName) -or $null -eq $Arguments[$ParameterName]) { return $default }
    $limit = [int]$Arguments[$ParameterName]
    if ($limit -lt 1) { return 1 }
    if ($limit -gt $max) { return $max }
    return $limit
}

# ---------------------------------------------------------------------------
# Rules: applicability, coverage, scopes
# ---------------------------------------------------------------------------
function Get-ScopeVCenters {
    <# vCenter names (declared and known) covered by a scope. 'vc:<name>' is an implicit per-vCenter scope. #>
    param([string]$ScopeName)
    $all = @($Script:VcenterConnections.Keys)
    if ($ScopeName -like 'vc:*') { $n = $ScopeName.Substring(3); return @($all | Where-Object { $_ -eq $n }) }
    if (-not $Script:Policy.Scopes.ContainsKey($ScopeName)) { return @() }
    $patterns = @($Script:Policy.Scopes[$ScopeName].VCenters)
    return @($all | Where-Object { Test-PatternList -Value $_ -Patterns $patterns })
}

function Get-ComputedRuleState {
    <# Rule states: active | inactive | suspended | upcoming | expired | exhausted #>
    param([hashtable]$Rule, [datetime]$Now = (Get-Date))
    if ($Rule.State -ne 'active') { return 'inactive' }
    if ($Script:RulesState.suspended.ContainsKey($Rule.Id)) { return 'suspended' }
    $v = $Rule.Validity
    if ($v.Start -and $Now -lt [datetime]$v.Start) { return 'upcoming' }
    if ($v.End -and $Now -gt [datetime]$v.End) { return 'expired' }
    if ($v.MaxUsage) {
        $u = if ($Script:RulesState.usages.ContainsKey($Rule.Id)) { [int]$Script:RulesState.usages[$Rule.Id] } else { 0 }
        if ($u -ge $v.MaxUsage) { return 'exhausted' }
    }
    return 'active'
}

function Test-RuleWindow {
    <# Days and hours of the rule at the given instant. StartTime > EndTime = window that crosses midnight. #>
    param([hashtable]$Rule, [datetime]$Now = (Get-Date))
    $v = $Rule.Validity
    if ($v.Days.Count -gt 0) {
        $day = [int]$Now.DayOfWeek; if ($day -eq 0) { $day = 7 }
        if ($day -notin $v.Days) { return $false }
    }
    if ($v.StartTime -and $v.EndTime) {
        $h = $Now.TimeOfDay; $d = [TimeSpan]::Parse($v.StartTime); $f = [TimeSpan]::Parse($v.EndTime)
        if ($d -le $f) { if ($h -lt $d -or $h -gt $f) { return $false } }
        else { if ($h -lt $d -and $h -gt $f) { return $false } }
    }
    return $true
}

function Test-RuleSubject {
    param([hashtable]$Rule, [hashtable]$Subject)   # Subject: @{ IP; Account; Groups }
    $s = $Rule.Subjects
    if ($Subject.IP -and (Test-PatternList -Value $Subject.IP -Patterns $s.Agents)) { return $true }
    if ($Subject.Account -and (Test-PatternList -Value $Subject.Account -Patterns $s.Accounts)) { return $true }
    foreach ($g in @($Subject.Groups)) { if (Test-PatternList -Value $g -Patterns $s.Groups) { return $true } }
    return $false
}

function Get-RuleCmdlets {
    <# Cmdlet patterns covered by a rule (expanded groups + direct cmdlets). #>
    param([hashtable]$Rule)
    $patterns = [System.Collections.Generic.List[string]]::new()
    foreach ($g in $Rule.Commands.Groups) { if ($Script:Policy.CommandGroups.ContainsKey($g)) { foreach ($c in $Script:Policy.CommandGroups[$g].Cmdlets) { $patterns.Add($c) } } }
    foreach ($c in $Rule.Commands.Cmdlets) { $patterns.Add($c) }
    return @($patterns | Select-Object -Unique)
}

function Test-RuleCovers {
    param([hashtable]$Rule, [string]$Command)
    if (Test-PatternList -Value $Command -Patterns @(Get-RuleCmdlets -Rule $Rule)) { return $true }
    if ($Command -in $Script:NonPowerCliTools -or $Command -eq 'Invoke-PowerCLI') { if (Test-PatternList -Value $Command -Patterns $Rule.Commands.Tools) { return $true } }
    return $false
}

function Get-ApplicableRules {
    param([hashtable]$Subject, [datetime]$Now = (Get-Date))
    return @($Script:Policy.Rules | Where-Object { (Get-ComputedRuleState -Rule $_ -Now $Now) -eq 'active' -and (Test-RuleSubject -Rule $_ -Subject $Subject) -and (Test-RuleWindow -Rule $_ -Now $Now) })
}

function Resolve-Decision {
    <#
    Full decision for a request. Commands = PowerCLI cmdlets of the line, or the name of the non-PowerCLI tool.
    Returns @{ Allowed; Reason; Rules (retained, Allow); VCenters (allowed for this request); Detail (per command) }
    #>
    param([Parameter(Mandatory)][hashtable]$Subject, [Parameter(Mandatory)][string[]]$Commands, [datetime]$Now = (Get-Date), [switch]$NoQuota)
    $applicable = @(Get-ApplicableRules -Subject $Subject -Now $Now)
    $denial = @($applicable | Where-Object { $_.Effect -eq 'Deny' })
    $authorizations = @($applicable | Where-Object { $_.Effect -eq 'Allow' })
    $detail = [ordered]@{}
    $kept = [System.Collections.Generic.List[hashtable]]::new()
    $vcenters = $null
    foreach ($command in @($Commands | Select-Object -Unique)) {
        $r = $denial | Where-Object { Test-RuleCovers -Rule $_ -Command $command } | Select-Object -First 1
        if ($r) { return @{ Allowed = $false; Reason = "$command denied by rule '$($r.Name)'"; Rules = @(); VCenters = @(); Detail = $detail; DenialRule = $r.Id } }
        $covering = @($authorizations | Where-Object { Test-RuleCovers -Rule $_ -Command $command })
        if ($covering.Count -eq 0) { return @{ Allowed = $false; Reason = "no rule allows $command for this subject"; Rules = @(); VCenters = @(); Detail = $detail } }
        $vcCommand = @($covering | ForEach-Object { foreach ($per in $_.Scopes) { Get-ScopeVCenters -ScopeName $per } } | Select-Object -Unique)
        $detail[$command] = [ordered]@{ rules = @($covering.Id); vcenters = $vcCommand }
        foreach ($c in $covering) { if (-not ($kept | Where-Object { $_.Id -eq $c.Id })) { $kept.Add($c) } }
        $vcenters = if ($null -eq $vcenters) { $vcCommand } else { @($vcenters | Where-Object { $_ -in $vcCommand }) }
    }
    if ($null -eq $vcenters) { $vcenters = @() }
    if (-not $NoQuota) {
        foreach ($r in $kept) {
            $limit = [int]$r.Limits.CallQuotaPerHour
            if ($limit -gt 0) {
                $key = "$($r.Id)|$($Subject.IP)"
                if (-not $Script:RuleCounters.ContainsKey($key)) { $Script:RuleCounters[$key] = [System.Collections.Generic.List[datetime]]::new() }
                $list = $Script:RuleCounters[$key]; $threshold = $Now.AddHours(-1)
                $list.RemoveAll({ param($h) $h -lt $threshold }) | Out-Null
                if ($list.Count -ge $limit) { return @{ Allowed = $false; Reason = "quota of rule '$($r.Name)' reached ($limit calls per hour)"; Rules = @(); VCenters = @(); Detail = $detail } }
            }
        }
    }
    return @{ Allowed = $true; Reason = ''; Rules = @($kept); VCenters = @($vcenters); Detail = $detail }
}

function Register-Execution {
    <# Called after a successful execution: increments quotas and usage counts (single use). #>
    param([hashtable]$Decision, [hashtable]$Subject)
    $change = $false
    foreach ($r in @($Decision.Rules)) {
        $key = "$($r.Id)|$($Subject.IP)"
        if (-not $Script:RuleCounters.ContainsKey($key)) { $Script:RuleCounters[$key] = [System.Collections.Generic.List[datetime]]::new() }
        $Script:RuleCounters[$key].Add((Get-Date))
        if ($r.Validity.MaxUsage) {
            $u = if ($Script:RulesState.usages.ContainsKey($r.Id)) { [int]$Script:RulesState.usages[$r.Id] } else { 0 }
            $Script:RulesState.usages[$r.Id] = $u + 1
            $change = $true
            if (($u + 1) -ge $r.Validity.MaxUsage) { Write-Journal -Level 'ADMIN' -Message "Rule '$($r.Name)' exhausted (usage $($u + 1)/$($r.Validity.MaxUsage))" -Data @{ rule = $r.Id; agent = $Subject.IP } }
        }
    }
    if ($change) { Save-RulesState }
}

function Get-RuleQuotaRemaining {
    param([hashtable]$Rule, [string]$IP)
    $limit = [int]$Rule.Limits.CallQuotaPerHour
    if ($limit -le 0) { return -1 }
    $key = "$($Rule.Id)|$IP"
    if (-not $Script:RuleCounters.ContainsKey($key)) { return $limit }
    $threshold = (Get-Date).AddHours(-1)
    return [math]::Max(0, $limit - @($Script:RuleCounters[$key] | Where-Object { $_ -ge $threshold }).Count)
}

function Get-AllowedVCenters {
    <# Per-agent view (console, Get-VIServer): union of the scopes of all its applicable Allow rules. #>
    param([string]$IPSource)
    $subject = (New-MIThrandirSubject -IP $IPSource)
    $rules = @(Get-ApplicableRules -Subject $subject | Where-Object { $_.Effect -eq 'Allow' })
    return @($rules | ForEach-Object { foreach ($per in $_.Scopes) { Get-ScopeVCenters -ScopeName $per } } | Select-Object -Unique)
}

function Test-Policy {
    <# MCP tool level, checked first. For PowerCLI tools the fine-grained decision comes next (Resolve-Decision on the cmdlets of the line). #>
    param([Parameter(Mandatory)][hashtable]$Tool, [Parameter(Mandatory)][hashtable]$Arguments, [Parameter(Mandatory)][string]$IPSource)
    if ($Script:GatewayState.suspended) { return @{ Allowed = $false; Reason = "gateway suspended by the administrator ($($Script:GatewayState.reason))" } }
    $suspensionKey = @($IPSource, [string]$Script:CurrentIdentity.Account) | Where-Object { $_ -and $Script:SuspendedAgents.ContainsKey($_) } | Select-Object -First 1
    if ($suspensionKey) {
        $suspension = $Script:SuspendedAgents[$suspensionKey]
        if ($suspension.Contains('sentinel')) { return @{ Allowed = $false; Reason = "agent $suspensionKey placed in quarantine by the MIThrandir Sentinel ($($suspension.reason)); an administrator must acknowledge it" } }
        return @{ Allowed = $false; Reason = "agent $suspensionKey suspended by the administrator ($($suspension.reason))" }
    }
    if ($Tool.Level -ne 'Read') { return @{ Allowed = $false; Reason = "level $($Tool.Level) not allowed" } }
    if (Get-Command -Name Test-SentinelAccess -ErrorAction SilentlyContinue) {
        $sentinel = Test-SentinelAccess -IP (Get-AgentKey -IP $IPSource) -ToolName $Tool.Name
        if (-not $sentinel.Allowed) { return @{ Allowed = $false; Reason = $sentinel.Reason } }
    }
    $subject = (New-MIThrandirSubject -IP $IPSource)
    if ($Tool.Name -eq 'Get-MIThrandirInventory') {
        # Inventory cache: same rights as the equivalent PowerCLI cmdlet (global allow list, then rules)
        $commands = @(Get-InventoryCmdlets -Arguments $Arguments)
        $g = Get-Global
        foreach ($c in $commands) {
            if (-not (Test-PatternList -Value $c -Patterns $g.AllowedCmdlets) -or $c -in $g.ExcludedCmdlets) { return @{ Allowed = $false; Reason = "cmdlet not allowed by the allow list (Global): $c" } }
        }
        $decision = Resolve-Decision -Subject $subject -Commands $commands
        if (-not $decision.Allowed) { return @{ Allowed = $false; Reason = "$($decision.Reason) (inventory cache read)" } }
        if (@($decision.VCenters).Count -eq 0) { return @{ Allowed = $false; Reason = "no vCenter in the scope of the agent for $($commands -join ', ')" } }
        return @{ Allowed = $true; Reason = ''; Decision = $decision; Subject = $subject }
    }
    if ($Tool.Name -in $Script:NonPowerCliTools) {
        $decision = Resolve-Decision -Subject $subject -Commands @($Tool.Name)
        if (-not $decision.Allowed) { return @{ Allowed = $false; Reason = $decision.Reason } }
        return @{ Allowed = $true; Reason = ''; Decision = $decision; Subject = $subject }
    }
    # PowerCLI tool: at least one applicable Allow rule is required; the per-cmdlet decision comes from validating the line
    $applicable = @(Get-ApplicableRules -Subject $subject | Where-Object { $_.Effect -eq 'Allow' -and (@(Get-RuleCmdlets -Rule $_).Count -gt 0 -or (Test-PatternList -Value 'Invoke-PowerCLI' -Patterns $_.Commands.Tools)) })
    if ($applicable.Count -eq 0) { return @{ Allowed = $false; Reason = "no rule allows this subject to run PowerCLI" } }
    return @{ Allowed = $true; Reason = ''; Subject = $subject }
}

function Invoke-Simulation {
    <# Console simulator: what would happen for this agent with this line, now or at a given date? Nothing is executed. #>
    param([string]$IPSource, [string]$Line, [string]$Tool = 'Invoke-PowerCLI', [datetime]$Now = (Get-Date))
    $subject = (New-MIThrandirSubject -IP $IPSource)
    $result = [ordered]@{ agent = $IPSource; instant = $Now.ToString('o'); line = $Line; stages = @() }
    $stages = [System.Collections.Generic.List[object]]::new()
    if ($Script:GatewayState.suspended) { $stages.Add(@{ stage = 'gateway'; ok = $false; detail = 'gateway suspended' }); $result.stages = $stages; $result.verdict = 'DENIED'; return $result }
    if ($Script:SuspendedAgents.ContainsKey($IPSource)) { $stages.Add(@{ stage = 'agent'; ok = $false; detail = 'agent suspended' }); $result.stages = $stages; $result.verdict = 'DENIED'; return $result }
    $applicable = @(Get-ApplicableRules -Subject $subject -Now $Now)
    $stages.Add(@{ stage = 'applicable rules'; ok = ($applicable.Count -gt 0); detail = (@($applicable | ForEach-Object { "$($_.Id) ($($_.Effect))" }) -join ', ') })
    if ($Tool -eq 'Get-MIThrandirInventory') {
        # Line = object type (VM, VMHost, Cluster, Datastore); empty = VM
        $type = if ([string]::IsNullOrWhiteSpace($Line)) { 'VM' } else { $Line.Trim() }
        $commands = @(Get-InventoryCmdlets -Arguments @{ Type = $type })
        $d = Resolve-Decision -Subject $subject -Commands $commands -Now $Now -NoQuota
        $stages.Add(@{ stage = "rights for $($commands -join ', ') (inventory cache)"; ok = $d.Allowed; detail = if ($d.Allowed) { "rules: $($d.Rules.Id -join ', '); vCenters: $($d.VCenters -join ', ')" } else { $d.Reason } })
        $result.stages = $stages; $result.verdict = if ($d.Allowed -and @($d.VCenters).Count -gt 0) { 'ALLOWED' } else { 'DENIED' }; return $result
    }
    if ($Tool -in $Script:NonPowerCliTools) {
        $d = Resolve-Decision -Subject $subject -Commands @($Tool) -Now $Now -NoQuota
        $stages.Add(@{ stage = 'decision'; ok = $d.Allowed; detail = if ($d.Allowed) { "rules: $($d.Rules.Id -join ', ')" } else { $d.Reason } })
        $result.stages = $stages; $result.verdict = if ($d.Allowed) { 'ALLOWED' } else { 'DENIED' }; return $result
    }
    $validation = Test-PowercliLine -Line $Line -IPSource $IPSource -Now $Now
    $stages.Add(@{ stage = 'syntax analysis'; ok = $validation.Ok; detail = if ($validation.Ok) { "cmdlets: $($validation.Cmdlets -join ', ')" } else { $validation.Reason } })
    if (-not $validation.Ok) { $result.stages = $stages; $result.verdict = 'DENIED'; return $result }
    $d = $validation.Decision
    $stages.Add(@{ stage = 'decision by rules'; ok = $d.Allowed; detail = if ($d.Allowed) { "rules kept: $($d.Rules.Id -join ', '); vCenters: $($d.VCenters -join ', ')" } else { $d.Reason } })
    if ($d.Allowed) {
        $stages.Add(@{ stage = 'line that would be executed'; ok = $true; detail = $validation.Line })
        foreach ($r in $d.Rules) { if ($r.Validity.MaxUsage) { $u = if ($Script:RulesState.usages.ContainsKey($r.Id)) { [int]$Script:RulesState.usages[$r.Id] } else { 0 }; $stages.Add(@{ stage = "usage of rule $($r.Id)"; ok = $true; detail = "$u / $($r.Validity.MaxUsage) consumed, this execution would consume one" }) } }
    }
    $result.stages = $stages; $result.verdict = if ($d.Allowed) { 'ALLOWED' } else { 'DENIED' }
    return $result
}

function Get-RulesView {
    <# For the console: rules with computed state, usage counts, observed per-agent quota. #>
    $now = Get-Date
    $hourThreshold = $now.AddHours(-1)
    return @($Script:Policy.Rules | ForEach-Object {
        $r = $_
        $callsHour = 0
        foreach ($key in @($Script:RuleCounters.Keys | Where-Object { $_ -like "$($r.Id)|*" })) { $callsHour += @($Script:RuleCounters[$key] | Where-Object { $_ -ge $hourThreshold }).Count }
        [ordered]@{
            id = $r.Id; name = $r.Name; comment = $r.Comment; flags = @($r.Flags); effect = $r.Effect; priority = $r.Priority; state = $r.State
            computedState = (Get-ComputedRuleState -Rule $r -Now $now); inWindow = (Test-RuleWindow -Rule $r -Now $now)
            subjects = $r.Subjects; commands = $r.Commands; expandedCmdlets = (Get-RuleCmdlets -Rule $r); scopes = $r.Scopes
            vcenters = @($r.Scopes | ForEach-Object { Get-ScopeVCenters -ScopeName $_ } | Select-Object -Unique)
            validity = $r.Validity; limits = $r.Limits; callsHour = $callsHour
            usage = if ($Script:RulesState.usages.ContainsKey($r.Id)) { [int]$Script:RulesState.usages[$r.Id] } else { 0 }
            suspension = if ($Script:RulesState.suspended.ContainsKey($r.Id)) { $Script:RulesState.suspended[$r.Id] } else { $null }
        }
    })
}
