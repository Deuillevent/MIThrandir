<#
.SYNOPSIS
    MIThrandir V2 execution sandbox: separate runspace, PowerCLI connected, unauthorized cmdlets invisible,
    ConstrainedLanguage, maximum timeout, bounded projection of results.

.DESCRIPTION
    Second wall, independent of the AST validation (Validation-AST.ps1). Even if a line passed validation,
    in this runspace it could only call the cmdlets left visible by the policy, with no .NET method or type
    calls (ConstrainedLanguage). The vCenter sessions live here; credentials are only presented at the
    moment of Connect-VIServer, with the sandbox unlocked, then the sandbox is locked again.

    Functions:
      - Initialize-Sandbox    : creates the runspace, imports PowerCLI, defines the projection function
      - Connect-VcenterInSandbox  : opens (or reopens) a vCenter session
      - Lock-Sandbox / Unlock-Sandbox
      - Get-SandboxCommand         : metadata of a command (alias resolution, parameters) for validation
      - Invoke-InSandbox          : runs a validated line, with timeout and bounds
#>

$Script:Sandbox = $null   # @{ Runspace; Commands (list of CommandInfo) ; Locked }

# ---------------------------------------------------------------------------
# Projection function, defined INSIDE the sandbox (in FullLanguage, before locking)
# ---------------------------------------------------------------------------
$Script:DefinitionProjection = @'
function Test-MIThrandirForbiddenPath {
    # Forbidden view path: equal to, or a descendant of, a forbidden one, but NOT an ancestor (we descend, then skip the forbidden child).
    param([string]$Path, [string[]]$Forbidden)
    $c = $Path.ToLowerInvariant()
    foreach ($f in $Forbidden) {
        $fl = $f.ToLowerInvariant()
        if ($c -eq $fl -or $c.StartsWith($fl + '.')) { return $true }
    }
    return $false
}

function ConvertTo-MIThrandirView {
    # Flattens a vSphere view object (VMware.Vim.*) into keys like "Config.Tools.ToolsVersion", skipping forbidden
    # paths (defense in depth, even if validation let them through) and rendering MoRefs as "Type-value".
    param($Object, [string]$Prefix, [System.Collections.Specialized.OrderedDictionary]$Target, [string[]]$Forbidden, [int]$Depth)
    if ($null -eq $Object -or $Depth -le 0) { return }
    foreach ($prop in $Object.PSObject.Properties) {
        if ($prop.MemberType -notin 'Property', 'NoteProperty') { continue }
        $path = if ($Prefix) { "$Prefix.$($prop.Name)" } else { [string]$prop.Name }
        if (Test-MIThrandirForbiddenPath -Path $path -Forbidden $Forbidden) { continue }
        $value = $null
        try { $value = $prop.Value } catch { continue }
        if ($null -eq $value) { continue }
        $typeName = ''
        try { $typeName = $value.GetType().FullName } catch { }
        if ($typeName -eq 'VMware.Vim.ManagedObjectReference') { $Target[$path] = "$($value.Type)-$($value.Value)"; continue }
        if ($value -is [string] -or $value -is [datetime] -or $value -is [enum] -or $value -is [ValueType]) {
            $Target[$path] = if ($value -is [datetime]) { $value.ToString('yyyy-MM-dd HH:mm:ss') } elseif ($value -is [double] -or $value -is [decimal]) { [math]::Round($value, 2) } elseif ($value -is [string]) { $value } else { "$value" }
            continue
        }
        if ($value -is [System.Collections.IEnumerable]) {
            $elements = @($value) | Select-Object -First 20
            $rendered = foreach ($e in $elements) {
                if ($null -eq $e) { continue }
                $tn = ''; try { $tn = $e.GetType().FullName } catch { }
                if ($tn -eq 'VMware.Vim.ManagedObjectReference') { "$($e.Type)-$($e.Value)" }
                elseif ($e -is [string] -or $e -is [ValueType]) { "$e" }
                else { $n = $null; try { $n = $e.Name } catch { }; if ($n) { "$n" } else { $e.GetType().Name } }
            }
            $Target[$path] = @($rendered)
            continue
        }
        # nested object (Config, Runtime, Tools, Summary...): descend into it
        ConvertTo-MIThrandirView -Object $value -Prefix $path -Target $Target -Forbidden $Forbidden -Depth ($Depth - 1)
    }
}

function ConvertTo-MIThrandirOutput {
    param([int]$Limit = 25, [string[]]$ExcludedProperties = @(), [hashtable]$ServersCard = @{}, [string[]]$ForbiddenPaths = @())
    begin { $account = 0; $total = 0; $output = [System.Collections.Generic.List[object]]::new() }
    process {
        $total++
        if ($account -ge $Limit -or $null -eq $_) { return }
        $account++
        $object = $_
        if ($object -is [string] -or $object -is [ValueType]) { $output.Add($object); return }

        # Raw vSphere view (Get-View): flattening of the requested paths, re-filtering of forbidden paths
        $fullType = ''
        try { $fullType = $object.GetType().FullName } catch { }
        if ($fullType -like 'VMware.Vim.*') {
            $viewRow = [ordered]@{}
            try {
                $url = [string]$object.Client.ServiceUrl
                if ($url -match '^https?://([^/]+)/') { $hp = $Matches[1]; $viewRow['vcenter'] = if ($ServersCard.ContainsKey($hp)) { $ServersCard[$hp] } else { $hp } }
            } catch { }
            try { if ($object.MoRef) { $viewRow['moref'] = "$($object.MoRef.Type)-$($object.MoRef.Value)" } } catch { }
            ConvertTo-MIThrandirView -Object $object -Prefix '' -Target $viewRow -Forbidden ($ForbiddenPaths + $ExcludedProperties) -Depth 8
            $output.Add($viewRow); return
        }

        $names = $null
        try { $set = $object.PSStandardMembers.DefaultDisplayPropertySet; if ($set) { $names = @($set.ReferencedPropertyNames) } } catch { }
        if (-not $names -or $names.Count -eq 0) {
            $names = @($object.PSObject.Properties | Where-Object { $_.MemberType -in 'Property', 'NoteProperty', 'AliasProperty', 'ScriptProperty' } | Select-Object -ExpandProperty Name)
        }
        $line = [ordered]@{}
        $uid = $null
        try { $uid = $object.Uid } catch { }
        if ($uid -is [string] -and $uid -match '^/VIServer=[^@]*@([^/]+)/') {
            $hotePort = $Matches[1]
            $line['vcenter'] = if ($ServersCard.ContainsKey($hotePort)) { $ServersCard[$hotePort] } else { $hotePort }
        }
        foreach ($name in $names) {
            if ($name -in $ExcludedProperties) { continue }
            $value = $null
            try { $value = $object.$name } catch { continue }
            $line[$name] = switch ($true) {
                ($null -eq $value)                                  { $null; break }
                ($value -is [string])                               { $value; break }
                ($value -is [datetime])                             { $value.ToString('yyyy-MM-dd HH:mm:ss'); break }
                ($value -is [enum] -or $value -is [ValueType])     { if ($value -is [double] -or $value -is [decimal]) { [math]::Round($value, 2) } else { "$value" }; break }
                ($value -is [System.Collections.IDictionary])       { "$($value.Count) entries"; break }
                ($value -is [System.Collections.IEnumerable])       {
                    $elements = @($value)
                    if ($elements.Count -eq 0) { @() }
                    elseif ($elements[0] -is [string] -or $elements[0] -is [ValueType]) { @($elements | Select-Object -First 20 | ForEach-Object { "$_" }) }
                    else { @($elements | Select-Object -First 20 | ForEach-Object { try { if ($null -ne $_.Name) { "$($_.Name)" } else { "$_" } } catch { "$_" } }) }
                    break
                }
                default {
                    $innerName = $null
                    try { $innerName = $value.Name } catch { }
                    if ($innerName) { "$innerName" } else { "$value" }
                }
            }
        }
        $output.Add($line)
    }
    end { [ordered]@{ total = $total; returned = $output.Count; truncated = ($total -gt $output.Count); objects = $output } }
}

function Select-MIThrandirScope {
    # Scope filter (V4.4) inserted by MIThrandir after each PowerCLI cmdlet when the scope is restricted.
    param([System.Collections.Generic.HashSet[string]]$Allowed, [string[]]$Free = @(), [bool]$InfraVisible = $false)
    process {
        $object = $_
        if ($null -eq $object) { return }
        # Raw vSphere view (Get-View): no Uid, but Client.ServiceUrl (server) and MoRef (type + VM id)
        $fullType = ''
        try { $fullType = $object.GetType().FullName } catch { }
        if ($fullType -like 'VMware.Vim.*') {
            $vServer = $null
            try { if ([string]$object.Client.ServiceUrl -match '^https?://([^/]+)/') { $vServer = $Matches[1] } } catch { }
            if (-not $vServer) { return }
            if ($Free -contains $vServer) { $object; return }
            $moref = $null; try { $moref = $object.MoRef } catch { }
            if ($moref -and $moref.Type -eq 'VirtualMachine') {
                if ($Allowed -and $Allowed.Contains("$vServer|$($moref.Value)")) { $object }
                return
            }
            if ($InfraVisible) { $object }
            return
        }
        $uid = $null
        try { $uid = $object.Uid } catch { }
        if (-not ($uid -is [string])) { try { $uid = $object.Entity.Uid } catch { } }
        if (-not ($uid -is [string])) { try { $uid = $object.VM.Uid } catch { } }
        if (-not ($uid -is [string]) -or $uid -notmatch '^/VIServer=[^@]*@([^/]+)/') { return }
        $server = $Matches[1]
        if ($Free -contains $server) { $object; return }
        if ($uid -match '/VirtualMachine=VirtualMachine-(vm-\d+)') {
            if ($Allowed -and $Allowed.Contains("$server|$($Matches[1])")) { $object }
            return
        }
        if ($InfraVisible) { $object }
    }
}
'@

function Initialize-Sandbox {
    param([Parameter(Mandatory)][array]$PowerCliModules)
    $initialState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $initialState.ThreadOptions = [System.Management.Automation.Runspaces.PSThreadOptions]::ReuseThread
    $runspace = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace($initialState)
    $runspace.Name = 'MIThrandirSandbox'
    $runspace.Open()
    $Script:Sandbox = @{ Runspace = $runspace; Commands = $null; Locked = $false }

    $preparation = @"
Import-Module VMware.VimAutomation.Core -ErrorAction Stop
$(($PowerCliModules | Where-Object { $_ -ne 'VMware.VimAutomation.Core' } | ForEach-Object { "Import-Module $_ -ErrorAction SilentlyContinue" }) -join "`n")
Set-PowerCLIConfiguration -Scope Session -ParticipateInCEIP `$false -InvalidCertificateAction Ignore -DefaultVIServerMode Multiple -Confirm:`$false | Out-Null
$Script:DefinitionProjection
"@
    $result = Invoke-RawInSandbox -Script $preparation
    if ($result.Errors.Count -gt 0) { throw "Sandbox preparation: $($result.Errors -join ' ; ')" }
    $Script:Sandbox.Commands = @($runspace.SessionStateProxy.InvokeCommand.GetCommands('*', 'All', $true))
    Write-Journal -Level 'INFO' -Message 'Sandbox created' -Data @{ loadedCommands = $Script:Sandbox.Commands.Count }
}

function Invoke-RawInSandbox {
    <# Execution without validation, reserved for initialization and connections (sandbox unlocked). #>
    param([Parameter(Mandatory)][string]$Script, [hashtable]$Parameters = @{}, [int]$DelaySeconds = 300)
    $ps = [PowerShell]::Create()
    $ps.Runspace = $Script:Sandbox.Runspace
    [void]$ps.AddScript($Script)
    foreach ($key in $Parameters.Keys) { [void]$ps.AddParameter($key, $Parameters[$key]) }
    try {
        $async = $ps.BeginInvoke()
        if (-not $async.AsyncWaitHandle.WaitOne($DelaySeconds * 1000)) {
            $ps.Stop()
            return @{ Output = @(); Errors = @("timeout of $DelaySeconds s exceeded, execution interrupted"); Interrupted = $true }
        }
        $output = @($ps.EndInvoke($async))
        $errors = @($ps.Streams.Error | ForEach-Object { $_.ToString() })
        $sync = [bool]@($ps.Streams.Error | Where-Object { $_.FullyQualifiedErrorId -like 'NotSupported,VMware.VimAutomation.*' -and $_.Exception -is [System.Management.Automation.PSNotSupportedException] }).Count
        return @{ Output = $output; Errors = $errors; Interrupted = $false; PowercliSync = $sync }
    }
    finally { $ps.Dispose() }
}

function Lock-Sandbox {
    <# Hides every command the policy does not allow, removes executables and scripts, then switches to ConstrainedLanguage. #>
    $proxy = $Script:Sandbox.Runspace.SessionStateProxy
    # Like JEA: no executable or external script reachable from the sandbox anymore
    if (-not $Script:Sandbox.ContainsKey('ApplicationsRemoved')) {
        Invoke-RawInSandbox -Script '$ExecutionContext.SessionState.Applications.Clear(); $ExecutionContext.SessionState.Scripts.Clear()' | Out-Null
        $Script:Sandbox.ApplicationsRemoved = $true
    }
    $visible = 0; $readOnly = 0
    foreach ($command in $Script:Sandbox.Commands) {
        if ($command.CommandType -notin 'Cmdlet', 'Function', 'Alias', 'Filter') { continue }
        $name = $command.Name
        $module = if ($command.ModuleName) { $command.ModuleName } else { '' }
        $alwaysDenied = if (Get-Variable -Name AlwaysDeniedCmdlets -Scope Script -ErrorAction SilentlyContinue) { $Script:AlwaysDeniedCmdlets } else { @() }
        $isAllowed = ($name -in 'ConvertTo-MIThrandirOutput', 'Select-MIThrandirScope', 'ConvertTo-MIThrandirView', 'Test-MIThrandirForbiddenPath') -or
                     ($name -in (Get-Global).Utilities) -or
                     ($module -like 'VMware.*' -and $command.CommandType -in 'Cmdlet', 'Function' -and (Test-PatternList -Value $name -Patterns (Get-Global).AllowedCmdlets) -and $name -notin (Get-Global).ExcludedCmdlets -and $name -notin $alwaysDenied)
        try {
            $command.Visibility = if ($isAllowed) { 'Public' } else { 'Private' }
            if ($isAllowed) { $visible++ }
        }
        catch { $readOnly++ }
    }
    $proxy.LanguageMode = [System.Management.Automation.PSLanguageMode]::ConstrainedLanguage
    $Script:Sandbox.Locked = $true
    Write-Journal -Level 'INFO' -Message 'Sandbox locked' -Data @{ visibleCommands = $visible; readOnly = $readOnly; language = 'ConstrainedLanguage' }
}

function Unlock-Sandbox {
    $proxy = $Script:Sandbox.Runspace.SessionStateProxy
    $proxy.LanguageMode = [System.Management.Automation.PSLanguageMode]::FullLanguage
    foreach ($command in $Script:Sandbox.Commands) { try { $command.Visibility = 'Public' } catch { } }
    $Script:Sandbox.Locked = $false
}

function Get-SandboxCommand {
    <# Resolves a name (aliases included) to the sandbox's CommandInfo. $null if unknown. #>
    param([Parameter(Mandatory)][string]$Name)
    $info = $Script:Sandbox.Runspace.SessionStateProxy.InvokeCommand.GetCommand($Name, 'All')
    if ($null -eq $info) { return $null }
    if ($info.CommandType -eq 'Alias') { $info = $info.ResolvedCommand }
    return $info
}

function Connect-VcenterInSandbox {
    param([Parameter(Mandatory)][string]$Name, [switch]$AcceptAnyCertificate)
    $entry = $Script:VcenterConnections[$Name]
    $block = $entry.Config
    $port = if ($block.ContainsKey('Port') -and $block.Port) { [int]$block.Port } else { 443 }
    $wasLocked = $Script:Sandbox.Locked
    if (-not $entry.Credential) {
        if (-not $entry.Error) { $entry.Error = 'credential missing: enter it in the console (Global settings, vCenters)' }
        $entry.Connection = $null
        return $false
    }
    try {
        Test-VcenterCertificate -Block $block -AcceptAnyCertificate:$AcceptAnyCertificate
        if ($wasLocked) { Unlock-Sandbox }
        $script = @'
param($Server, $Port, $Credential, $Old)
if ($Old) { Disconnect-VIServer -Server $Old -Confirm:$false -ErrorAction SilentlyContinue }
Connect-VIServer -Server $Server -Port $Port -Credential $Credential -ErrorAction Stop
'@
        $result = Invoke-RawInSandbox -Script $script -Parameters @{ Server = $block.Server; Port = $port; Credential = $entry.Credential; Old = $entry.Connection } -DelaySeconds 120
        if ($result.Errors.Count -gt 0 -or $result.Output.Count -eq 0) { throw ($result.Errors -join ' ; ') }
        $entry.Connection = $result.Output[0]
        $entry.Error = ''
        Write-Journal -Level 'INFO' -Message "Connected to $Name" -Data @{ server = $entry.Connection.Name; version = $entry.Connection.Version; build = $entry.Connection.Build; account = $entry.Credential.UserName }
        return $true
    }
    catch {
        $entry.Connection = $null
        $entry.Error = $_.Exception.Message
        Write-Journal -Level 'ERROR' -Message "Connection to $Name failed: $($_.Exception.Message)" -Data @{ server = $block.Server }
        return $false
    }
    finally {
        if ($wasLocked) { Lock-Sandbox }
    }
}

function Disconnect-VcenterInSandbox {
    <# V4.5: removal of a vCenter from the console. Closes the sandbox's PowerCLI session, then locks again. #>
    param([Parameter(Mandatory)][string]$Name)
    $entry = $Script:VcenterConnections[$Name]
    if (-not $entry -or -not $entry.Connection -or -not $Script:Sandbox) { return }
    $wasLocked = $Script:Sandbox.Locked
    try {
        if ($wasLocked) { Unlock-Sandbox }
        [void](Invoke-RawInSandbox -Script 'param($Old) Disconnect-VIServer -Server $Old -Confirm:$false -ErrorAction SilentlyContinue' -Parameters @{ Old = $entry.Connection } -DelaySeconds 60)
        Write-Journal -Level 'INFO' -Message "Session closed: $Name"
    }
    catch { Write-Journal -Level 'ERROR' -Message "Closing session $Name failed: $($_.Exception.Message)" }
    finally {
        $entry.Connection = $null
        if ($wasLocked) { Lock-Sandbox }
    }
}

function Assert-VcenterConnection {
    param([Parameter(Mandatory)][string]$Name)
    $entry = $Script:VcenterConnections[$Name]
    if ($entry.Connection -and $entry.Connection.IsConnected) { return $true }
    Write-Journal -Level 'INFO' -Message "Session $Name missing or expired, reconnecting"
    return (Connect-VcenterInSandbox -Name $Name -AcceptAnyCertificate:$Script:AcceptAnyCertificate)
}

function Get-ServersCard {
    <# FQDN -> short name, to tag the returned objects. #>
    $card = @{}
    foreach ($entry in $Script:VcenterConnections.Values) {
        $port = if ($entry.Config.ContainsKey('Port') -and $entry.Config.Port) { [int]$entry.Config.Port } else { 443 }
        $card["$($entry.Config.Server):$port"] = $entry.Name
        if ($entry.Connection) { $card["$($entry.Connection.Name):$($entry.Connection.Port)"] = $entry.Name }
    }
    return $card
}

function Sync-VariablesPowerCLI {
    <# Synchronizes the PowerCLI variables in FullLanguage for the duration of one fixed command, then returns to ConstrainedLanguage. #>
    $proxy = $Script:Sandbox.Runspace.SessionStateProxy
    $proxy.LanguageMode = [System.Management.Automation.PSLanguageMode]::FullLanguage
    try { [void](Invoke-RawInSandbox -Script '$null = Get-Datacenter -Server $MIThrandirServers -Name mithrandir-sync-nonexistent -ErrorAction SilentlyContinue' -DelaySeconds 30) }
    catch { }
    finally { $proxy.LanguageMode = [System.Management.Automation.PSLanguageMode]::ConstrainedLanguage }
}

function Invoke-InSandbox {
    <# Runs a line ALREADY validated and rewritten by Validation-AST.ps1, with the context variables, in the locked sandbox. #>
    param(
        [Parameter(Mandatory)][string]$Line,
        [Parameter(Mandatory)][string[]]$Servers,
        [int]$Limit = 25,
        [hashtable]$Filter = $null
    )
    if (-not $Script:Sandbox.Locked) { throw 'Sandbox not locked: execution denied' }
    $proxy = $Script:Sandbox.Runspace.SessionStateProxy
    $objects = @(foreach ($name in $Servers) { $Script:VcenterConnections[$name].Connection })
    $proxy.SetVariable('MIThrandirServers', $objects)
    foreach ($entry in $Script:VcenterConnections.Values) {
        $proxy.SetVariable(('MIThrandirServer_' + ($entry.Name -replace '[^A-Za-z0-9_]', '_')), $entry.Connection)
    }
    $proxy.SetVariable('MIThrandirExcludedProperties', [string[]]@((Get-Global).ExcludedProperties))
    $proxy.SetVariable('MIThrandirServerMap', (Get-ServersCard))
    $proxy.SetVariable('MIThrandirLimit', [int]$Limit)
    $viewPaths = @(if ((Get-Global).ContainsKey('Views') -and (Get-Global).Views.ContainsKey('ForbiddenPaths')) { (Get-Global).Views.ForbiddenPaths } else { @() })
    $proxy.SetVariable('MIThrandirForbiddenPaths', [string[]]$viewPaths)
    # Scope (V4.4): sets used by Select-MIThrandirScope (inserted into the line by Add-ScopeFilterLine)
    $allowed = if ($Filter -and $Filter.Allowed) { $Filter.Allowed } else { [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase) }
    $proxy.SetVariable('MIThrandirScope', $allowed)
    $proxy.SetVariable('MIThrandirFreeScope', [string[]]@(if ($Filter) { $Filter.Free } else { @() }))
    $proxy.SetVariable('MIThrandirInfraVisible', [bool]($Filter -and $Filter.InfraVisible))

    $fullLine = "$Line | ConvertTo-MIThrandirOutput -Limit `$MIThrandirLimit -ExcludedProperties `$MIThrandirExcludedProperties -ServersCard `$MIThrandirServerMap -ForbiddenPaths `$MIThrandirForbiddenPaths"
    $result = Invoke-RawInSandbox -Script $fullLine -DelaySeconds ([int](Get-Global).MaxDelaySeconds)
    if ($result.PowercliSync -and -not $result.Interrupted) {
        # PowerCLI resynchronizes $DefaultVIServer and $DefaultVIServers (AllScope variables) at the start of its cmdlets;
        # in ConstrainedLanguage this write is forbidden (PSNotSupportedException "Specified method is not supported").
        # We trigger the synchronization in FullLanguage with a FIXED command (no agent input), then replay the line.
        Sync-VariablesPowerCLI
        Write-Journal -Level 'INFO' -Message 'PowerCLI variables resynchronized, line replayed' -Data @{ servers = $Servers }
        $result = Invoke-RawInSandbox -Script $fullLine -DelaySeconds ([int](Get-Global).MaxDelaySeconds)
    }
    return $result
}
