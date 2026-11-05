<#
.SYNOPSIS
    Automatic inventory of MIThrandir V4.1: cache of the VMs, hosts, clusters and datastores of each vCenter,
    refreshed in the background, to answer bulk reads without querying the vCenters again.

.DESCRIPTION
    - A dedicated pwsh PROCESS (Inventory-Background.ps1, separate from the server and the sandbox) opens its own PowerCLI sessions and re-reads each vCenter,
      one at a time, every Inventory.IntervalSeconds (300 by default). Tags are re-read once every
      Inventory.CycleTags cycles (6 by default), because Get-TagAssignment is expensive.
    - Lightweight read through Get-View with targeted -Property lists. Get-View remains forbidden to agents: only MIThrandir uses it here.
    - The process writes one JSON snapshot per vCenter (Inventory.Folder); the server reloads it when the file changes,
      and at startup: the cache is available immediately, flagged "disk" (disk) until the first cycle has run.
    - Agents access it through the MCP tool Get-MIThrandirInventory. Its rights are EXACTLY those of the equivalent
      PowerCLI cmdlet (Get-VM, Get-VMHost, Get-Cluster, Get-Datastore, and Get-TagAssignment when filtering by tag):
      same rules, same vCenter scopes, same quotas, same log. The real cmdlets are never
      redirected to the cache: PowerCLI parity is preserved.

    Configuration (MIThrandir.config.psd1, optional):
        Inventory = @{ Active = $true; IntervalSeconds = 300; CycleTags = 6; Folder = 'inventory'; MaxLimit = 500 }
#>

$Script:InventoryTypes = [ordered]@{ VM = 'Get-VM'; VMHost = 'Get-VMHost'; Cluster = 'Get-Cluster'; Datastore = 'Get-Datastore' }
$Script:Inventory = [hashtable]::Synchronized(@{
    active = $false; interval = 300; cycleTags = 6; cycle = 0; request = $false; stop = $false
    inProgress = ''; lastCycle = ''; next = ''; backgroundError = ''; folder = ''; dates = @{}; vcErrors = @{}
    vcenters = [hashtable]::Synchronized(@{})
})
$Script:InventoryBackground = $null

function Get-InventoryConfig {
    $cfg = @{ Active = $true; IntervalSeconds = 300; CycleTags = 6; Folder = 'inventory'; MaxLimit = 500 }
    if ($Script:Config.ContainsKey('Inventory') -and $Script:Config.Inventory -is [hashtable]) {
        foreach ($key in @($Script:Config.Inventory.Keys)) { $cfg[$key] = $Script:Config.Inventory[$key] }
    }
    # Settings made from the console: they take precedence over MIThrandir.config.psd1 (the folder path still comes from the psd1)
    $cfg.Source = 'MIThrandir.config.psd1'
    $file = Get-InventorySettingsFile -Folder $cfg.Folder
    if ($file -and (Test-Path $file)) {
        try {
            $console = [System.IO.File]::ReadAllText($file) | ConvertFrom-Json -AsHashtable
            foreach ($key in @('Active', 'IntervalSeconds', 'CycleTags', 'MaxLimit')) { if ($console.ContainsKey($key) -and $null -ne $console[$key]) { $cfg[$key] = $console[$key] } }
            $when = if ($console.date -is [datetime]) { $console.date.ToString('dd.MM.yyyy HH:mm') } else { [string]$console.date }
            $cfg.Source = "console ($($console.author), $when)"
        }
        catch { }
    }
    $cfg.Active = [bool]$cfg.Active
    $cfg.IntervalSeconds = [math]::Max(30, [int]$cfg.IntervalSeconds)
    $cfg.CycleTags = [math]::Max(1, [int]$cfg.CycleTags)
    $cfg.MaxLimit = [math]::Max(1, [int]$cfg.MaxLimit)
    return $cfg
}

function Get-InventorySettingsFile {
    param([string]$Folder)
    if (-not (Get-Command Resolve-RelativePath -ErrorAction SilentlyContinue)) { return $null }
    return (Join-Path (Resolve-RelativePath $Folder) 'settings-console.json')
}

function Set-InventorySettings {
    <# From the console: enables, disables or changes the frequency, live (the background process is restarted). #>
    param([Parameter(Mandatory)][hashtable]$Settings, [Parameter(Mandatory)][string]$Author)
    $current = Get-InventoryConfig
    $newItem = [ordered]@{
        Active              = if ($Settings.ContainsKey('active')) { [bool]$Settings.active } else { $current.Active }
        IntervalSeconds = if ($Settings.ContainsKey('intervalSeconds')) { [int]$Settings.intervalSeconds } else { $current.IntervalSeconds }
        CycleTags          = if ($Settings.ContainsKey('cycleTags')) { [int]$Settings.cycleTags } else { $current.CycleTags }
        MaxLimit          = if ($Settings.ContainsKey('maxLimit')) { [int]$Settings.maxLimit } else { $current.MaxLimit }
        author = $Author; date = (Get-Date).ToString('o')
    }
    if ($newItem.IntervalSeconds -lt 30 -or $newItem.IntervalSeconds -gt 86400) { throw 'period: between 30 and 86400 seconds' }
    if ($newItem.CycleTags -lt 1 -or $newItem.CycleTags -gt 1000) { throw 'tag cycle: between 1 and 1000' }
    if ($newItem.MaxLimit -lt 1 -or $newItem.MaxLimit -gt 10000) { throw 'objects per response: between 1 and 10000' }
    $file = Get-InventorySettingsFile -Folder $current.Folder
    $folder = Split-Path $file -Parent
    if (-not (Test-Path $folder)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
    [System.IO.File]::WriteAllText($file, ($newItem | ConvertTo-Json), [System.Text.UTF8Encoding]::new($false))
    Write-Journal -Level 'ADMIN' -Message "Automatic inventory: $(if ($newItem.Active) { "enabled, every $($newItem.IntervalSeconds) s" } else { 'disabled' })" -Data @{ author = $Author; active = $newItem.Active; intervalSeconds = $newItem.IntervalSeconds; cycleTags = $newItem.CycleTags; maxLimit = $newItem.MaxLimit }
    # Live application: stop the background process, then restart it if enabled; the MCP tool appears or disappears
    Stop-AutomaticInventory
    if ($newItem.Active -and $Script:WithActiveVCenter) { Start-AutomaticInventory -AcceptAnyCertificate:$Script:AcceptAnyCertificate }
    $Script:Catalog = Get-ToolCatalog -WithVCenter:$Script:WithActiveVCenter
    return (Get-InventoryState)
}

function Get-InventoryFileName([string]$Name) { return ("inventory-{0}.json" -f ($Name -replace '[^A-Za-z0-9._-]', '_')) }

function Start-AutomaticInventory {
    <# Starts Inventory-Background.ps1 in a separate pwsh process (PowerCLI cannot be loaded in two runspaces of the server). #>
    param([switch]$AcceptAnyCertificate)
    $cfg = Get-InventoryConfig
    if (-not $cfg.Active) { Write-Journal -Level 'INFO' -Message 'Automatic inventory disabled (Inventory.Active = $false)'; return }
    $folder = Resolve-RelativePath $cfg.Folder
    if (-not (Test-Path $folder)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
    $Script:Inventory.folder = $folder
    $Script:Inventory.interval = $cfg.IntervalSeconds
    $Script:Inventory.cycleTags = $cfg.CycleTags
    $Script:Inventory.dates = @{}
    Remove-Item (Join-Path $folder 'request.flag'), (Join-Path $folder 'state-background.json') -Force -ErrorAction SilentlyContinue

    # Description of the vCenters for the background process: DPAPI file paths, never the secrets themselves
    $blocks = @(foreach ($entry in @($Script:VcenterConnections.Values | Where-Object { $_.Credential })) {
        $port = if ($entry.Config.ContainsKey('Port') -and $entry.Config.Port) { [int]$entry.Config.Port } else { 443 }
        $thumbprint = if ($entry.Config.ContainsKey('CertificateThumbprint')) { ([string]$entry.Config.CertificateThumbprint).Replace(':', '').Replace(' ', '').ToUpperInvariant() } else { '' }
        [ordered]@{ Name = $entry.Name; Server = $entry.Config.Server; Port = $port; CredentialFile = (Resolve-RelativePath $entry.Config.CredentialFile); Thumbprint = $thumbprint }
    })
    $blocksFile = Join-Path $folder 'vcenters.json'
    [System.IO.File]::WriteAllText($blocksFile, (ConvertTo-Json -InputObject $blocks -Depth 4), [System.Text.UTF8Encoding]::new($false))

    # Snapshots from the last shutdown: available right away, flagged "disk" (disk) until the first cycle
    Update-InventoryFromDisk -Source 'disk'

    $script = Join-Path $Script:RootPath 'Inventory-Background.ps1'
    if (-not (Test-Path $script)) { throw "Inventory-Background.ps1 not found: $script" }
    $pwsh = (Get-Process -Id $PID).Path
    $arguments = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', "`"$script`"", '-Folder', "`"$folder`"", '-BlocksFile', "`"$blocksFile`"", '-Interval', $cfg.IntervalSeconds, '-CycleTags', $cfg.CycleTags, '-PidParent', $PID)
    if ($AcceptAnyCertificate) { $arguments += '-AcceptAll' }
    $process = Start-Process -FilePath $pwsh -ArgumentList $arguments -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $folder 'background-output.txt') -RedirectStandardError (Join-Path $folder 'background-error.txt')
    $Script:InventoryBackground = $process
    $Script:Inventory.active = $true
    Write-Journal -Level 'INFO' -Message 'Automatic inventory started' -Data @{ intervalSeconds = $cfg.IntervalSeconds; cycleTags = $cfg.CycleTags; folder = $folder; vcenters = @($blocks | ForEach-Object { $_.Name }); snapshots = @($Script:Inventory.vcenters.Keys); pid = $process.Id }
}

function Update-InventoryFromDisk {
    <# Reloads a snapshot when the background process has rewritten it (file date). Cheap call otherwise. #>
    param([string]$Source = '')
    $folder = $Script:Inventory.folder
    if (-not $folder) { return }
    if (-not $Script:Inventory.ContainsKey('dates')) { $Script:Inventory.dates = @{} }
    foreach ($name in @($Script:VcenterConnections.Keys)) {
        $file = Join-Path $folder (Get-InventoryFileName $name)
        if (-not (Test-Path $file)) { continue }
        $date = (Get-Item $file).LastWriteTimeUtc
        if ($Script:Inventory.dates.ContainsKey($name) -and $Script:Inventory.dates[$name] -eq $date) { continue }
        try {
            $lu = [System.IO.File]::ReadAllText($file) | ConvertFrom-Json -AsHashtable -Depth 8
            if ($Source) { $lu.source = $Source }
            $Script:Inventory.vcenters[$name] = $lu
            $Script:Inventory.dates[$name] = $date
        }
        catch { Write-Journal -Level 'ERROR' -Message "Unreadable inventory snapshot: $file" -Data @{ error = $_.Exception.Message } }
    }
    $stateFile = Join-Path $folder 'state-background.json'
    if (Test-Path $stateFile) {
        try {
            $e = [System.IO.File]::ReadAllText($stateFile) | ConvertFrom-Json -AsHashtable
            foreach ($key in @('cycle', 'inProgress', 'lastCycle', 'next', 'backgroundError')) { $Script:Inventory[$key] = $e[$key] }
            $Script:Inventory.vcErrors = if ($e.vcErrors) { $e.vcErrors } else { @{} }
        }
        catch { }
    }
    if ($Script:InventoryBackground -and $Script:InventoryBackground.HasExited -and $Script:Inventory.active) {
        $Script:Inventory.active = $false
        $detail = ''
        try { $detail = (Get-Content (Join-Path $folder 'background-error.txt') -Tail 3 -ErrorAction SilentlyContinue) -join ' ' } catch { }
        $Script:Inventory.backgroundError = "inventory process stopped (code $($Script:InventoryBackground.ExitCode)) $detail".Trim()
        Write-Journal -Level 'ERROR' -Message "Automatic inventory: background process stopped" -Data @{ code = $Script:InventoryBackground.ExitCode; detail = $detail }
    }
}

function Stop-AutomaticInventory {
    if (-not $Script:InventoryBackground) { return }
    try { if (-not $Script:InventoryBackground.HasExited) { $Script:InventoryBackground.Kill($true) } } catch { }
    $Script:InventoryBackground = $null
    $Script:Inventory.active = $false
}

function Request-InventoryRefresh {
    if (-not $Script:Inventory.folder) { throw "automatic inventory is not enabled" }
    [System.IO.File]::WriteAllText((Join-Path $Script:Inventory.folder 'request.flag'), (Get-Date).ToString('o'))
}

function Get-AgeSeconds([string]$Timestamp) {
    if (-not $Timestamp) { return $null }
    return [int]((Get-Date) - [datetime]::Parse($Timestamp, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)).TotalSeconds
}

function Get-InventoryState {
    <# Console and dashboard view: freshness and volumes per vCenter, without the objects. #>
    Update-InventoryFromDisk
    $errors = if ($Script:Inventory.ContainsKey('vcErrors') -and $Script:Inventory.vcErrors) { $Script:Inventory.vcErrors } else { @{} }
    $list = @(foreach ($name in @($Script:VcenterConnections.Keys)) {
        $e = $Script:Inventory.vcenters[$name]
        $vcError = if ($errors.ContainsKey($name)) { [string]$errors[$name] } else { '' }
        if ($null -eq $e) { [ordered]@{ name = $name; source = 'none'; timestamp = ''; ageSeconds = $null; durationMs = 0; vms = 0; hosts = 0; clusters = 0; datastores = 0; tagsTimestamp = ''; tagsError = ''; error = $vcError }; continue }
        [ordered]@{
            name = $name; source = $e.source; timestamp = $e.timestamp; ageSeconds = (Get-AgeSeconds $e.timestamp); durationMs = $e.durationMs
            vms = @($e.vms).Count; hosts = @($e.hosts).Count; clusters = @($e.clusters).Count; datastores = @($e.datastores).Count
            taggedObjects = @($e.tags.Keys).Count; tagsTimestamp = $e.tagsTimestamp; tagsError = $e.tagsError; error = $vcError
        }
    })
    $cfg = Get-InventoryConfig
    return [ordered]@{
        active = [bool]$Script:Inventory.active; configuredActive = $cfg.Active; intervalSeconds = $cfg.IntervalSeconds; cycleTags = $cfg.CycleTags; maxLimit = $cfg.MaxLimit; settingsSource = $cfg.Source
        cycle = $Script:Inventory.cycle; inProgress = $Script:Inventory.inProgress; lastCycle = $Script:Inventory.lastCycle; next = $Script:Inventory.next
        pendingRequest = [bool]($Script:Inventory.folder -and (Test-Path (Join-Path $Script:Inventory.folder 'request.flag'))); backgroundError = $Script:Inventory.backgroundError; vcenters = $list
    }
}

function Get-InventoryCmdlets {
    <# PowerCLI cmdlets the agent must be entitled to for this cache read (rights parity). #>
    param([hashtable]$Arguments)
    $type = if ($Arguments.ContainsKey('Type') -and $Arguments.Type) { [string]$Arguments.Type } else { 'VM' }
    if (-not $Script:InventoryTypes.Contains($type)) { throw "Unknown type: $type (values: $($Script:InventoryTypes.Keys -join ', '))" }
    $commands = @($Script:InventoryTypes[$type])
    if ($Arguments.ContainsKey('Tag') -and $Arguments.Tag) { $commands += 'Get-TagAssignment' }
    return $commands
}

function Search-Inventory {
    param([hashtable]$Arguments, [string[]]$VCenters, [hashtable]$Filter = $null)
    Update-InventoryFromDisk
    $cfg = Get-InventoryConfig
    $type = if ($Arguments.ContainsKey('Type') -and $Arguments.Type) { [string]$Arguments.Type } else { 'VM' }
    $field = @{ VM = 'vms'; VMHost = 'hosts'; Cluster = 'clusters'; Datastore = 'datastores' }[$type]
    $requests = @(if ($Arguments.ContainsKey('Server') -and $Arguments.Server) { @($Arguments.Server) | ForEach-Object { [string]$_ } } else { @($VCenters) })
    $outOfScope = @($requests | Where-Object { $_ -notin $VCenters })
    if ($outOfScope.Count -gt 0) { throw "vCenter outside the scope allowed for this agent: $($outOfScope -join ', ')" }
    $pattern = { param($key) if ($Arguments.ContainsKey($key) -and $Arguments[$key]) { [string]$Arguments[$key] } else { $null } }
    $name = & $pattern 'Name'; $cluster = & $pattern 'Cluster'; $folder = & $pattern 'Folder'; $tag = & $pattern 'Tag'; $state = & $pattern 'PowerState'
    $excluded = @((Get-Global).ExcludedProperties)

    $freshness = [System.Collections.Generic.List[object]]::new()
    $found = [System.Collections.Generic.List[object]]::new()
    foreach ($vc in $requests) {
        $e = $Script:Inventory.vcenters[$vc]
        if ($null -eq $e) { $freshness.Add([ordered]@{ vCenter = $vc; available = $false; reason = 'not inventoried yet' }); continue }
        $vcError = if ($Script:Inventory.ContainsKey('vcErrors') -and $Script:Inventory.vcErrors -and $Script:Inventory.vcErrors.ContainsKey($vc)) { [string]$Script:Inventory.vcErrors[$vc] } else { '' }
        $freshness.Add([ordered]@{ vCenter = $vc; available = $true; timestamp = $e.timestamp; ageSeconds = (Get-AgeSeconds $e.timestamp); source = $e.source; lastCycleError = $vcError; tagsTimestamp = $e.tagsTimestamp })
        foreach ($o in @($e[$field])) {
            if ($Filter -and $Filter.Restricted -and -not (Get-InventoryFilterScope -Filter $Filter -VCenter $vc -Object $o -Type $type)) { continue }
            if ($name -and $o.Name -notlike $name) { continue }
            if ($cluster -and $o.Contains('Cluster') -and $o.Cluster -notlike $cluster) { continue }
            if ($folder -and $o.Contains('FolderPath') -and $o.FolderPath -notlike $folder -and $o.Folder -notlike $folder) { continue }
            if ($state -and $o.Contains('PowerState') -and $o.PowerState -ne $state) { continue }
            $tagKey = @{ VM = 'VirtualMachine-'; VMHost = 'HostSystem-'; Cluster = 'ClusterComputeResource-'; Datastore = 'Datastore-' }[$type] + $o.Id
            $objectTags = @(if ($e.tags -and $e.tags.ContainsKey($tagKey)) { $e.tags[$tagKey] } else { @() })
            if ($tag -and -not ($objectTags | Where-Object { $_ -like $tag -or ($_ -split '/', 2)[-1] -like $tag })) { continue }
            $copy = [ordered]@{}
            foreach ($k in $o.Keys) { if ($k -notin $excluded) { $copy[$k] = $o[$k] } }
            $copy.Tags = $objectTags
            $found.Add($copy)
        }
    }
    $result = [ordered]@{ source = 'MIThrandir inventory cache'; type = $type; total = $found.Count; freshness = @($freshness) }
    if ($Filter -and $Filter.Restricted) { $result.scope = [ordered]@{ filter = $true; visibleVms = $Filter.VmCount; infrastructureVisible = $Filter.InfraVisible } }
    if ($Arguments.ContainsKey('GroupBy') -and $Arguments.GroupBy) {
        $key = [string]$Arguments.GroupBy
        $result.groups = @($found | Group-Object { $v = $_[$key]; if ($v -is [array]) { $v -join ',' } else { [string]$v } } | Sort-Object Count -Descending | ForEach-Object { [ordered]@{ value = $_.Name; quantity = $_.Count } })
        return $result
    }
    $limit = $cfg.MaxLimit
    if ($Arguments.ContainsKey('Limit') -and $Arguments.Limit) { $limit = [math]::Min($cfg.MaxLimit, [math]::Max(1, [int]$Arguments.Limit)) }
    $properties = @(if ($Arguments.ContainsKey('Property') -and $Arguments.Property) { @($Arguments.Property) | ForEach-Object { [string]$_ } } else { @() })
    $objects = @($found | Sort-Object { $_.Name } | Select-Object -First $limit | ForEach-Object {
        if ($properties.Count -eq 0) { $_ } else { $o = $_; $p = [ordered]@{ Name = $o.Name; vCenter = $o.vCenter }; foreach ($k in $properties) { if ($o.Contains($k)) { $p[$k] = $o[$k] } }; $p }
    })
    $result.returned = $objects.Count
    if ($found.Count -gt $objects.Count) { $result.continuation = "result limited to $limit objects: refine the filters, use Property to reduce, or GroupBy to count" }
    $result.objects = $objects
    return $result
}

function New-InventoryTool {
    $cfg = Get-InventoryConfig
    return @{
        Name = 'Get-MIThrandirInventory'; Title = 'Cached inventory'; Level = 'Read'
        Description = "Fast read of the inventory cached by MIThrandir (refreshed every $($cfg.IntervalSeconds) s), without querying the vCenters. Preferred for bulk reads (thousands of VMs, counts, searches by cluster, folder or tag). Types: VM, VMHost, Cluster, Datastore. Wildcard filters: Name, Cluster, Folder, Tag (Category/Name or Name). GroupBy counts by property (e.g. Cluster, PowerState, GuestOS, vCenter). The response gives the data age per vCenter; for a value accurate to the second, use the PowerCLI cmdlet. Same rights as the equivalent cmdlet (Get-VM, Get-VMHost, Get-Cluster, Get-Datastore)."
        InputSchema = @{
            type = 'object'
            properties = [ordered]@{
                Type = @{ type = 'string'; enum = @($Script:InventoryTypes.Keys); description = 'Object type. Default: VM.' }
                Server = @{ type = 'array'; items = @{ type = 'string' }; description = 'Short vCenter names. Omitted = all allowed vCenters.' }
                Name = @{ type = 'string'; description = 'Name pattern, wildcards * and ? accepted.' }
                Cluster = @{ type = 'string'; description = 'Cluster pattern (VM, VMHost).' }
                Folder = @{ type = 'string'; description = 'Folder or folder path pattern (VM, Cluster).' }
                Tag = @{ type = 'string'; description = 'vSphere tag pattern, Category/Name or Name alone.' }
                PowerState = @{ type = 'string'; enum = @('PoweredOn', 'PoweredOff', 'Suspended'); description = 'VM power state.' }
                Property = @{ type = 'array'; items = @{ type = 'string' }; description = 'Properties to return (Name and vCenter always included).' }
                GroupBy = @{ type = 'string'; description = 'Returns a count per value of this property instead of the objects.' }
                Limit = @{ type = 'integer'; minimum = 1; maximum = $cfg.MaxLimit; description = "Maximum objects returned (default and maximum $($cfg.MaxLimit))." }
            }
            additionalProperties = $false
        }
        Action = {
            param([hashtable]$Arguments, [hashtable]$Context)
            if (-not $Script:Inventory.active) { throw "automatic inventory is disabled on this gateway" }
            $decision = $Context.Decision
            $scopeFilter = if (Get-Command -Name Get-ScopeFilter -ErrorAction SilentlyContinue) { Get-ScopeFilter -Decision $decision -VCenters @($decision.VCenters) } else { $null }
            $result = Search-Inventory -Arguments $Arguments -VCenters @($decision.VCenters) -Filter $scopeFilter
            Register-Execution -Decision $decision -Subject @{ IP = $Context.IPSource }
            return $result
        }
    }
}
