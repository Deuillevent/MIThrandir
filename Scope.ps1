<#
.SYNOPSIS
    Scopes inside vCenters (MIThrandir V4.4): tags, clusters, folders, VM name patterns.

.DESCRIPTION
    A scope whose only restriction is the vCenter list opens those vCenters entirely (V4 behavior).
    If it carries criteria (Tags, Clusters, Folders, VmPatterns), it covers only the VMs that match them:
      - between two criteria types: AND (e.g. cluster CLUSTER-SQL-PRD AND tag App/APP-A);
      - within one type: OR (e.g. App/APP-A OR App/APP-B);
      - for tags, grouped by category: OR within a category, AND between categories
        (App/APP-A + Env/Production = application APP-A in production only).
    The retained VMs are computed on the inventory cache (refreshed in the background). Filtering is applied
    BEFORE objects continue down the pipeline: MIThrandir inserts Select-MIThrandirScope after each PowerCLI
    cmdlet of the line. A VM outside the scope therefore does not exist for the agent, even inside a Measure-Object.
    Infrastructure objects (hosts, clusters, datastores, networks) are hidden, unless a restricted scope
    carries InfraVisible = $true. A VM missing from the cache (created less than one cycle ago) is denied.
#>

function Test-RestrictedScope {
    param([hashtable]$Scope)
    if ($null -eq $Scope) { return $false }
    foreach ($key in @('Tags', 'Clusters', 'Folders', 'VmPatterns')) { if (@($Scope[$key] | Where-Object { $_ }).Count -gt 0) { return $true } }
    return $false
}

function Test-Pattern {
    <# PowerShell wildcard (*, ?); a pattern starting with ^ is a regular expression. #>
    param([string]$Value, [string]$Pattern)
    if ($Pattern.StartsWith('^')) { return ($Value -match $Pattern) }
    return ($Value -like $Pattern)
}

function Test-VmScope {
    <# Does a VM from the cache (hashtable: Name, Cluster, Folder, FolderPath, Tags) meet the scope criteria? #>
    param([System.Collections.IDictionary]$VM, [hashtable]$Scope, [string[]]$TagsVM = @())
    $clusters = @($Scope["Clusters"] | Where-Object { $_ })
    if ($clusters.Count -gt 0 -and -not ($clusters | Where-Object { Test-Pattern -Value ([string]$VM["Cluster"]) -Pattern $_ })) { return $false }
    $folders = @($Scope["Folders"] | Where-Object { $_ })
    if ($folders.Count -gt 0 -and -not ($folders | Where-Object { (Test-Pattern -Value ([string]$VM["FolderPath"]) -Pattern $_) -or (Test-Pattern -Value ([string]$VM["Folder"]) -Pattern $_) -or ([string]$VM["FolderPath"] -like "$_/*") })) { return $false }
    $patterns = @($Scope["VmPatterns"] | Where-Object { $_ })
    if ($patterns.Count -gt 0 -and -not ($patterns | Where-Object { Test-Pattern -Value ([string]$VM["Name"]) -Pattern $_ })) { return $false }
    $tags = @($Scope["Tags"] | Where-Object { $_ })
    if ($tags.Count -gt 0) {
        # Grouping by category: "App/APP-A" -> category App; bare "APP-A" -> any category
        $byCategory = @{}
        foreach ($t in $tags) {
            $cat, $val = if ($t -match '^([^/]+)/(.+)$') { $Matches[1], $Matches[2] } else { '*', $t }
            if (-not $byCategory.ContainsKey($cat)) { $byCategory[$cat] = [System.Collections.Generic.List[string]]::new() }
            $byCategory[$cat].Add($val)
        }
        foreach ($cat in $byCategory.Keys) {
            $ok = $false
            foreach ($tv in $TagsVM) {
                $c, $v = if ($tv -match '^([^/]+)/(.+)$') { $Matches[1], $Matches[2] } else { '', $tv }
                if ($cat -ne '*' -and $c -ne $cat) { continue }
                if ($byCategory[$cat] | Where-Object { Test-Pattern -Value $v -Pattern $_ }) { $ok = $true; break }
            }
            if (-not $ok) { return $false }
        }
    }
    return $true
}

function Get-VmsScope {
    <# VMs of a vCenter cache covered by a scope: list of hashtables (Name, Id, ...). #>
    param([string]$VCenter, [hashtable]$Scope)
    if (Get-Command -Name Update-InventoryFromDisk -ErrorAction SilentlyContinue) { Update-InventoryFromDisk }
    $e = $Script:Inventory.vcenters[$VCenter]
    if ($null -eq $e) { return $null }
    $result = [System.Collections.Generic.List[object]]::new()
    foreach ($vm in @($e.vms)) {
        $key = "VirtualMachine-$($vm.Id)"
        $tagsVM = @(if ($e.tags -and $e.tags.ContainsKey($key)) { $e.tags[$key] } else { @() })
        if (Test-VmScope -VM $vm -Scope $Scope -TagsVM $tagsVM) { $result.Add($vm) }
    }
    return $result
}

function Get-VcenterAddress {
    <# "host:port" as it appears in the Uid of PowerCLI objects. #>
    param([string]$Name)
    $entry = $Script:VcenterConnections[$Name]
    if ($entry.Connection) { return "$($entry.Connection.Name):$($entry.Connection.Port)" }
    $port = if ($entry.Config.ContainsKey('Port') -and $entry.Config.Port) { [int]$entry.Config.Port } else { 443 }
    return "$($entry.Config.Server):$port"
}

function Get-ScopeFilter {
    <#
    Filter to apply for a given decision and set of vCenters.
    Returns @{ Restricted; Free (fully open host:port); Allowed (HashSet "host:port|vm-N");
              IdsPerVCenter (name -> HashSet of VM Ids); InfraVisible; VmCount; Warnings }
    #>
    param([hashtable]$Decision, [string[]]$VCenters)
    $filter = @{ Restricted = $false; Free = [System.Collections.Generic.List[string]]::new(); Allowed = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                 IdsPerVCenter = @{}; InfraVisible = $false; VmCount = 0; Warnings = [System.Collections.Generic.List[string]]::new(); FreeVCenters = [System.Collections.Generic.List[string]]::new() }
    $scopes = @($Decision.Rules | ForEach-Object { $_.Scopes } | Where-Object { $_ } | Select-Object -Unique)
    foreach ($vc in $VCenters) {
        $covering = @($scopes | Where-Object { $vc -in @(Get-ScopeVCenters -ScopeName $_) })
        $free = $false
        $restrictedList = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($name in $covering) {
            if ($name -like 'vc:*') { $free = $true; break }
            $per = $Script:Policy.Scopes[$name]
            if (-not (Test-RestrictedScope -Scope $per)) { $free = $true; break }
            $restrictedList.Add($per)
        }
        $address = Get-VcenterAddress -Name $vc
        if ($free -or $restrictedList.Count -eq 0) { $filter.Free.Add($address); $filter.FreeVCenters.Add($vc); continue }
        $filter.Restricted = $true
        $ids = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($per in $restrictedList) {
            if ($per.ContainsKey('InfraVisible') -and $per.InfraVisible) { $filter.InfraVisible = $true }
            $vms = Get-VmsScope -VCenter $vc -Scope $per
            if ($null -eq $vms) { $filter.Warnings.Add("inventory of $vc unavailable: no VM is visible until the cache is loaded"); continue }
            foreach ($vm in $vms) { [void]$ids.Add([string]$vm.Id); [void]$filter.Allowed.Add("$address|$($vm.Id)") }
        }
        $filter.IdsPerVCenter[$vc] = $ids
        $filter.VmCount += $ids.Count
    }
    return $filter
}

function Add-ScopeFilterLine {
    <#
    Inserts "| Select-MIThrandirScope ..." after each PowerCLI cmdlet of the pipeline (line already validated and rewritten).
    Rejects a line in which a PowerCLI cmdlet would be nested (script block, subexpression): it would escape the filter.
    #>
    param([string]$Line)
    $tokens = $null; $errors = $null
    $tree = [System.Management.Automation.Language.Parser]::ParseInput($Line, [ref]$tokens, [ref]$errors)
    $pipeline = $tree.EndBlock.Statements[0]
    if ($pipeline -isnot [System.Management.Automation.Language.PipelineAst]) { return @{ Ok = $false; Reason = 'line cannot be filtered by the scope' } }
    $top = [System.Collections.Generic.HashSet[object]]::new()
    foreach ($el in $pipeline.PipelineElements) { [void]$top.Add($el) }
    foreach ($c in $tree.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {
        if ($top.Contains($c)) { continue }
        $name = $c.GetCommandName()
        $info = if ($name) { Get-SandboxCommand -Name $name } else { $null }
        if ($info -and ([string]$info.ModuleName) -like 'VMware.*') { return @{ Ok = $false; Reason = "nested PowerCLI cmdlet ($name): not permitted with a restricted scope, write it in the main pipeline" } }
    }
    $chunks = foreach ($el in $pipeline.PipelineElements) {
        $text = $el.Extent.Text
        if ($el -is [System.Management.Automation.Language.CommandAst]) {
            $name = $el.GetCommandName()
            $info = if ($name) { Get-SandboxCommand -Name $name } else { $null }
            if ($info -and ([string]$info.ModuleName) -like 'VMware.*') { $text += ' | Select-MIThrandirScope -Allowed $MIThrandirScope -Free $MIThrandirFreeScope -InfraVisible $MIThrandirInfraVisible' }
        }
        $text
    }
    return @{ Ok = $true; Line = ($chunks -join ' | ') }
}

function Get-InventoryFilterScope {
    <# For Get-MIThrandirInventory: cache objects allowed by the filter. #>
    param([hashtable]$Filter, [string]$VCenter, [System.Collections.IDictionary]$Object, [string]$Type)
    if (-not $Filter -or -not $Filter.Restricted -or $VCenter -in $Filter.FreeVCenters) { return $true }
    if ($Type -eq 'VM') { return ($Filter.IdsPerVCenter.ContainsKey($VCenter) -and $Filter.IdsPerVCenter[$VCenter].Contains([string]$Object.Id)) }
    return [bool]$Filter.InfraVisible
}

function Get-InventoryTree {
    <# For the console (Scopes page): vCenter > datacenter > cluster, folders and tags with VM counts. #>
    if (Get-Command -Name Update-InventoryFromDisk -ErrorAction SilentlyContinue) { Update-InventoryFromDisk }
    $result = foreach ($name in @($Script:VcenterConnections.Keys)) {
        $e = $Script:Inventory.vcenters[$name]
        if ($null -eq $e) { [ordered]@{ name = $name; available = $false }; continue }
        $vms = @($e.vms)
        $datacenters = @($e.clusters | Group-Object { $_.Datacenter } | ForEach-Object {
            [ordered]@{ name = $_.Name; clusters = @($_.Group | Sort-Object Name | ForEach-Object { $c = $_.Name; [ordered]@{ name = $c; hosts = $_.NumHosts; vms = @($vms | Where-Object { $_.Cluster -eq $c }).Count } }) }
        })
        $folders = @($vms | Where-Object { $_.FolderPath } | Group-Object { $_.FolderPath } | Sort-Object Name | ForEach-Object { [ordered]@{ path = $_.Name; vms = $_.Count } })
        $accounts = @{}
        if ($e.tags) { foreach ($key in @($e.tags.Keys)) { if ($key -notlike 'VirtualMachine-*') { continue }; foreach ($t in @($e.tags[$key])) { if ($accounts.ContainsKey($t)) { $accounts[$t]++ } else { $accounts[$t] = 1 } } } }
        $categories = @($accounts.Keys | Group-Object { ($_ -split '/', 2)[0] } | Sort-Object Name | ForEach-Object {
            [ordered]@{ category = $_.Name; valueList = @($_.Group | Sort-Object | ForEach-Object { [ordered]@{ value = ($_ -split '/', 2)[1]; vms = $accounts[$_] } }) }
        })
        [ordered]@{ name = $name; available = $true; timestamp = $e.timestamp; vms = $vms.Count; datacenters = $datacenters; folders = $folders; tags = $categories; tagsTimestamp = $e.tagsTimestamp }
    }
    return @{ vcenters = @($result) }
}

function Get-ScopePreview {
    <# For the console: how many VMs, and which, a scope would cover (before saving). #>
    param([hashtable]$Scope)
    $vcs = @($Script:VcenterConnections.Keys | Where-Object { Test-PatternList -Value $_ -Patterns @($Scope.VCenters) })
    $restricted = Test-RestrictedScope -Scope $Scope
    $byVc = foreach ($vc in $vcs) {
        $e = $Script:Inventory.vcenters[$vc]
        if (-not $restricted) { [ordered]@{ vcenter = $vc; vms = $(if ($e) { @($e.vms).Count } else { $null }); examples = @(); whole = $true }; continue }
        $vms = Get-VmsScope -VCenter $vc -Scope $Scope
        [ordered]@{ vcenter = $vc; vms = $(if ($null -eq $vms) { $null } else { $vms.Count }); examples = @($vms | Select-Object -First 12 | ForEach-Object { $_.Name }); whole = $false }
    }
    return [ordered]@{ restricted = $restricted; vcenters = @($byVc); total = (@($byVc | ForEach-Object { [int]$_.vms }) | Measure-Object -Sum).Sum }
}
