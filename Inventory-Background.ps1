<#
.SYNOPSIS
    Inventory process of MIThrandir V4.1, started and stopped by MIThrandir-MCP.ps1 (Inventory.ps1). Do not start by hand.

.DESCRIPTION
    SEPARATE pwsh process from the server: PowerCLI loaded in two runspaces of the same process malfunctions
    ("Specified method is not supported" in the sandbox). Isolating the inventory in its own process
    removes this conflict and also separates the vCenter sessions from those of the agents.
    Read: Get-View with targeted -Property lists. Write: one JSON snapshot per vCenter and state-background.json in -Folder.
    Exchange with the server through files: request.flag (refresh now), stop if the parent process disappears.
    Credentials: DPAPI files from the configuration, decryptable only by the same account on the same machine.
#>
param(
    [Parameter(Mandatory)][string]$Folder,
    [Parameter(Mandatory)][string]$BlocksFile,
    [int]$Interval = 300,
    [int]$CycleTags = 6,
    [int]$PidParent = 0,
    [switch]$AcceptAll
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Off
$Blocks = @(Get-Content -Path $BlocksFile -Raw | ConvertFrom-Json -AsHashtable)
$State = @{ interval = [math]::Max(30, $Interval); cycleTags = [math]::Max(1, $CycleTags); cycle = 0; stop = $false; inProgress = ''; lastCycle = ''; next = ''; backgroundError = ''; startup = (Get-Date).ToString('o'); vcenters = @{}; vcErrors = @{} }
$stateFile = Join-Path $Folder 'state-background.json'
$requestFile = Join-Path $Folder 'request.flag'

function Save-BackgroundState {
    $view = [ordered]@{ pid = $PID; cycle = $State.cycle; inProgress = $State.inProgress; lastCycle = $State.lastCycle; next = $State.next; backgroundError = $State.backgroundError; startup = $State.startup; interval = $State.interval; cycleTags = $State.cycleTags; vcErrors = $State.vcErrors; upd = (Get-Date).ToString('o') }
    try { [System.IO.File]::WriteAllText($stateFile + '.tmp', ($view | ConvertTo-Json -Depth 4 -Compress), [System.Text.UTF8Encoding]::new($false)); Move-Item ($stateFile + '.tmp') $stateFile -Force } catch { }
}

# Previous snapshots: tags not re-read in this cycle are carried over
foreach ($b in $Blocks) {
    $f = Join-Path $Folder ("inventory-{0}.json" -f ($b.Name -replace '[^A-Za-z0-9._-]', '_'))
    if (Test-Path $f) { try { $State.vcenters[$b.Name] = [System.IO.File]::ReadAllText($f) | ConvertFrom-Json -AsHashtable -Depth 8 } catch { } }
}
try {
    Import-Module VMware.VimAutomation.Core -ErrorAction Stop
    Set-PowerCLIConfiguration -Scope Session -ParticipateInCEIP $false -InvalidCertificateAction Ignore -DefaultVIServerMode Multiple -Confirm:$false | Out-Null
}
catch { $State.backgroundError = "PowerCLI unavailable for the inventory: $($_.Exception.Message)"; Save-BackgroundState; exit 1 }
Save-BackgroundState

function Get-BackgroundThumbprint([string]$HostName, [int]$Port) {
    $client = [System.Net.Sockets.TcpClient]::new(); $stream = $null
    try {
        $client.Connect($HostName, $Port)
        $stream = [System.Net.Security.SslStream]::new($client.GetStream(), $false, { param($a, $b, $c, $d) $true })
        $stream.AuthenticateAsClient($HostName)
        return ([System.Security.Cryptography.X509Certificates.X509Certificate2]::new($stream.RemoteCertificate)).Thumbprint
    }
    finally { if ($stream) { $stream.Dispose() }; $client.Dispose() }
}
function Get-Key($Ref) { if ($null -eq $Ref) { return '' } ; return "$($Ref.Type)-$($Ref.Value)" }

$sessions = @{}
while (-not $State.stop) {
    $State.cycle++
    $withTags = ((($State.cycle - 1) % $State.cycleTags) -eq 0)
    foreach ($b in $Blocks) {
        if ($State.stop) { break }
        $State.inProgress = $b.Name
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $precedent = $State.vcenters[$b.Name]
        try {
            $vi = $sessions[$b.Name]
            if (-not $vi -or -not $vi.IsConnected) {
                if (-not $AcceptAll) {
                    $present = Get-BackgroundThumbprint -HostName $b.Server -Port $b.Port
                    if ($b.Thumbprint -and $present -ne $b.Thumbprint) { throw "unexpected certificate ($present), connection denied" }
                    if (-not $b.Thumbprint) { throw 'no certificate thumbprint configured' }
                }
                $credential = Import-Clixml -Path $b.CredentialFile
                $vi = Connect-VIServer -Server $b.Server -Port $b.Port -Credential $credential -NotDefault -ErrorAction Stop
                $sessions[$b.Name] = $vi
            }
            $folders = @{}; foreach ($x in @(Get-View -Server $vi -ViewType Folder -Property Name, Parent)) { $folders[(Get-Key $x.MoRef)] = $x }
            $centers = @{}; foreach ($x in @(Get-View -Server $vi -ViewType Datacenter -Property Name, Parent)) { $centers[(Get-Key $x.MoRef)] = $x.Name }
            $clusters = @{}; foreach ($x in @(Get-View -Server $vi -ViewType ClusterComputeResource -Property Name, Parent)) { $clusters[(Get-Key $x.MoRef)] = $x }
            $pools = @{}; foreach ($x in @(Get-View -Server $vi -ViewType ResourcePool -Property Name, Owner)) { $pools[(Get-Key $x.MoRef)] = $x }
            $banks = @{}; $bankList = @(Get-View -Server $vi -ViewType Datastore -Property Name, Summary.Capacity, Summary.FreeSpace, Summary.Type, Summary.Accessible)
            foreach ($x in $bankList) { $banks[(Get-Key $x.MoRef)] = $x.Name }

            # Object path: walk up the folders to the datacenter (the hidden vm/host/datastore folders are omitted)
            $pathOf = {
                param($Ref)
                $chunks = [System.Collections.Generic.List[string]]::new(); $center = ''
                $current = $Ref; $guard = 0
                while ($current -and $guard -lt 40) {
                    $guard++; $key = Get-Key $current
                    if ($folders.ContainsKey($key)) {
                        $name = $folders[$key].Name
                        if ($name -notin @('vm', 'host', 'datastore', 'network', 'Datacenters')) { $chunks.Insert(0, $name) }
                        $current = $folders[$key].Parent; continue
                    }
                    if ($centers.ContainsKey($key)) { $center = $centers[$key]; break }
                    break
                }
                return @{ Folder = $(if ($chunks.Count) { $chunks[$chunks.Count - 1] } else { '' }); Path = ($chunks -join '/'); Datacenter = $center }
            }

            $hosts = @{}; $hostList = [System.Collections.Generic.List[object]]::new()
            foreach ($x in @(Get-View -Server $vi -ViewType HostSystem -Property Name, Parent, Runtime.ConnectionState, Runtime.InMaintenanceMode, Runtime.PowerState, Summary.Hardware.CpuModel, Summary.Hardware.NumCpuCores, Summary.Hardware.MemorySize, Config.Product.Version, Config.Product.Build)) {
                $parentKey = Get-Key $x.Parent
                $clusterName = if ($clusters.ContainsKey($parentKey)) { $clusters[$parentKey].Name } else { '' }
                $hosts[(Get-Key $x.MoRef)] = @{ Name = $x.Name; Cluster = $clusterName }
                $hostList.Add([ordered]@{
                    Name = $x.Name; Cluster = $clusterName; ConnectionState = [string]$x.Runtime.ConnectionState; InMaintenance = [bool]$x.Runtime.InMaintenanceMode
                    PowerState = [string]$x.Runtime.PowerState; CpuModel = $x.Summary.Hardware.CpuModel; NumCpuCores = $x.Summary.Hardware.NumCpuCores
                    MemoryGB = [math]::Round(([double]$x.Summary.Hardware.MemorySize) / 1GB, 1); Version = $x.Config.Product.Version; Build = $x.Config.Product.Build
                    Id = $x.MoRef.Value; vCenter = $b.Name
                })
            }
            $clusterList = @(foreach ($c in $clusters.Values) {
                $ch = & $pathOf $c.Parent
                [ordered]@{ Name = $c.Name; Datacenter = $ch.Datacenter; Folder = $ch.Path; NumHosts = @($hosts.Values | Where-Object { $_.Cluster -eq $c.Name }).Count; Id = $c.MoRef.Value; vCenter = $b.Name }
            })
            $dsList = @(foreach ($x in $bankList) {
                [ordered]@{ Name = $x.Name; Type = $x.Summary.Type; CapacityGB = [math]::Round(([double]$x.Summary.Capacity) / 1GB, 1); FreeSpaceGB = [math]::Round(([double]$x.Summary.FreeSpace) / 1GB, 1); Accessible = [bool]$x.Summary.Accessible; Id = $x.MoRef.Value; vCenter = $b.Name }
            })
            $vmList = [System.Collections.Generic.List[object]]::new()
            foreach ($x in @(Get-View -Server $vi -ViewType VirtualMachine -Property Name, Parent, ResourcePool, Runtime.PowerState, Runtime.Host, Config.Template, Config.Hardware.NumCPU, Config.Hardware.MemoryMB, Config.GuestFullName, Guest.IpAddress, Guest.HostName, Guest.ToolsRunningStatus, Datastore, Summary.Storage.Committed)) {
                $vmHost = $hosts[(Get-Key $x.Runtime.Host)]
                $ch = & $pathOf $x.Parent
                $vmList.Add([ordered]@{
                    Name = $x.Name; PowerState = [string]$x.Runtime.PowerState; NumCpu = $x.Config.Hardware.NumCPU
                    MemoryGB = [math]::Round(([double]$x.Config.Hardware.MemoryMB) / 1024, 1); GuestOS = $x.Config.GuestFullName
                    IPAddress = $x.Guest.IpAddress; GuestHostName = $x.Guest.HostName; ToolsRunningStatus = $x.Guest.ToolsRunningStatus
                    VMHost = $(if ($vmHost) { $vmHost.Name } else { '' }); Cluster = $(if ($vmHost) { $vmHost.Cluster } else { '' })
                    Folder = $ch.Folder; FolderPath = $ch.Path; Datacenter = $ch.Datacenter
                    ResourcePool = $(if ($pools.ContainsKey((Get-Key $x.ResourcePool))) { $pools[(Get-Key $x.ResourcePool)].Name } else { '' })
                    Datastores = @($x.Datastore | ForEach-Object { $banks[(Get-Key $_)] } | Where-Object { $_ })
                    UsedSpaceGB = [math]::Round(([double]$x.Summary.Storage.Committed) / 1GB, 1); Template = [bool]$x.Config.Template
                    Id = $x.MoRef.Value; vCenter = $b.Name
                })
            }

            # Tags: one cycle out of CycleTags; otherwise keep those from the previous cycle
            $tags = if ($precedent -and $precedent.tags) { $precedent.tags } else { @{} }
            $tagsTimestamp = if ($precedent) { $precedent.tagsTimestamp } else { '' }
            $tagsError = if ($precedent) { $precedent.tagsError } else { '' }
            if ($withTags) {
                try {
                    $newItems = @{}
                    foreach ($a in @(Get-TagAssignment -Server $vi -ErrorAction Stop)) {
                        $id = [string]$a.Entity.Id; if (-not $id) { continue }
                        $value = "$($a.Tag.Category.Name)/$($a.Tag.Name)"
                        if (-not $newItems.ContainsKey($id)) { $newItems[$id] = [System.Collections.Generic.List[string]]::new() }
                        $newItems[$id].Add($value)
                    }
                    $tags = @{}; foreach ($k in $newItems.Keys) { $tags[$k] = @($newItems[$k]) }
                    $tagsTimestamp = (Get-Date).ToString('o'); $tagsError = ''
                }
                catch { $tagsError = 'tags unavailable on this vCenter: ' + (($_.Exception.Message -replace '\s+', ' ').Trim()) }
            }
            $stopwatch.Stop()
            $entry = @{
                name = $b.Name; timestamp = (Get-Date).ToString('o'); durationMs = $stopwatch.ElapsedMilliseconds; error = ''; source = 'vcenter'
                vms = @($vmList); hosts = @($hostList); clusters = @($clusterList); datastores = @($dsList)
                tags = $tags; tagsTimestamp = $tagsTimestamp; tagsError = $tagsError
            }
            $State.vcenters[$b.Name] = $entry; $State.vcErrors.Remove($b.Name)
            $State.inProgress = ''; Save-BackgroundState
            try {
                if (-not (Test-Path $Folder)) { New-Item -ItemType Directory -Path $Folder -Force | Out-Null }
                $file = Join-Path $Folder ("inventory-{0}.json" -f ($b.Name -replace '[^A-Za-z0-9._-]', '_'))
                [System.IO.File]::WriteAllText($file + '.tmp', ($entry | ConvertTo-Json -Depth 6 -Compress), [System.Text.UTF8Encoding]::new($false))
                Move-Item -Path ($file + '.tmp') -Destination $file -Force
            }
            catch { }
        }
        catch {
            $stopwatch.Stop()
            $sessions.Remove($b.Name)
            $State.vcErrors[$b.Name] = $_.Exception.Message
            Save-BackgroundState
        }
    }
    $State.inProgress = ''
    $State.lastCycle = (Get-Date).ToString('o')
    $State.next = (Get-Date).AddSeconds($State.interval).ToString('o')
    Save-BackgroundState
    $waiting = 0
    while (-not $State.stop -and $waiting -lt $State.interval) {
        if (Test-Path $requestFile) { Remove-Item $requestFile -Force -ErrorAction SilentlyContinue; break }
        if (-not (Get-Process -Id $PidParent -ErrorAction SilentlyContinue)) { $State.stop = $true; break }
        Start-Sleep -Seconds 1; $waiting++
    }
}
foreach ($s in $sessions.Values) { try { Disconnect-VIServer -Server $s -Confirm:$false -ErrorAction SilentlyContinue } catch { } }
