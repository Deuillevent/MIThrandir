<#
.SYNOPSIS
    MIThrandir V4.1 administration console: JSON API + HTML page, served by a second HttpListener
    with Windows integrated authentication (Negotiate/Kerberos/NTLM), restricted to the groups in the configuration.

.DESCRIPTION
    Routes (all under the console prefix, http://+:8766/ by default):
      GET  /                          HTML page (no external resource, works offline)
      GET  /api/state                 global state: gateway, vCenters, sandbox, counters, export, active policy
      GET  /api/agents                declared and observed agents, counters, remaining quota, suspension
      POST /api/agents/suspend      { ip, reason }      POST /api/agents/resume { ip }
      POST /api/gateway/suspend  { reason }          POST /api/gateway/resume
      GET  /api/policy             active policy and metadata
      GET  /api/policy/versions    history
      POST /api/policy             { policy, comment } -> new version, applied live
      POST /api/policy/restore   { version }
      GET  /api/journal?since=&level=&agent=&text=&limit=
      GET  /api/journal/export?format=jsonl|csv&level=&agent=&text=
      GET  /api/export                SIEM export status     POST /api/export/test
      GET  /api/vcenters              POST /api/vcenters/reconnect { name }
      GET  /api/vcenters/config       POST /api/vcenters/certificate { server, port }
      POST /api/vcenters/save  { newItem, name, zone, server, port, thumbprint, account, password, description }
      POST /api/vcenters/remove    { name }     (V4.5: vCenter list managed from the console, applied live)
      GET  /api/rules                POST /api/rules/flags { id, flags }   (and /state, /suspend, /resume, /remove)
      GET  /api/inventory   GET /api/inventory/tree   POST /api/scopes/preview   POST /api/inventory/refresh   GET /api/inventory/objects?Type=&Name=&Cluster=&Tag=&GroupBy=
      GET  /api/activity?agent=&hours=   (logged activity of an agent, aggregated by cmdlet: "from activity to a rule")
    Every POST action is logged at ADMIN level with the Windows identity of its author.
#>

function Test-ConsoleAccess {
    param([System.Net.HttpListenerContext]$Context)
    $identity = $Context.User
    if ($null -eq $identity -or -not $identity.Identity.IsAuthenticated) { return @{ Ok = $false; Reason = 'not authenticated'; Name = '' } }
    $name = $identity.Identity.Name
    $cfg = $Script:Config.Console
    $groups = @(if ($cfg.ContainsKey('AllowedGroups')) { @($cfg.AllowedGroups) } else { @() })
    $users = @(if ($cfg.ContainsKey('AllowedUsers')) { @($cfg.AllowedUsers) } else { @() })
    if ($users | Where-Object { $_ -ieq $name }) { return @{ Ok = $true; Name = $name } }
    $principal = [System.Security.Principal.WindowsPrincipal]::new([System.Security.Principal.WindowsIdentity]$identity.Identity)
    if ($groups.Count -eq 0 -and $users.Count -eq 0) {
        if ($principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) { return @{ Ok = $true; Name = $name } }
        return @{ Ok = $false; Reason = "$name is not a local administrator (no group configured)"; Name = $name }
    }
    foreach ($group in $groups) {
        try { if ($principal.IsInRole($group)) { return @{ Ok = $true; Name = $name } } } catch { }
    }
    return @{ Ok = $false; Reason = "$name belongs to no allowed group"; Name = $name }
}

function Read-JsonBody {
    param([System.Net.HttpListenerRequest]$Request)
    $reader = New-Object System.IO.StreamReader($Request.InputStream, $Request.ContentEncoding)
    $body = $reader.ReadToEnd(); $reader.Close()
    if ([string]::IsNullOrWhiteSpace($body)) { return @{} }
    return ($body | ConvertFrom-Json -AsHashtable -Depth 20)
}

function Get-GlobalState {
    $vcenters = @(foreach ($e in $Script:VcenterConnections.Values) {
        [ordered]@{ name = $e.Name; zone = $(if ($e.Config.ContainsKey('Zone') -and $e.Config.Zone) { [string]$e.Config.Zone } else { '' }); server = $e.Config.Server; connected = [bool]($e.Connection -and $e.Connection.IsConnected); version = if ($e.Connection) { $e.Connection.Version } else { $null }; account = $(if ($e.Credential) { $e.Credential.UserName } else { '' }); error = $e.Error }
    })
    $sbx = if ($Script:Sandbox) { [ordered]@{ exists = $true; locked = $Script:Sandbox.Locked; visibleCommands = @($Script:Sandbox.Commands | Where-Object { $_.Visibility -eq 'Public' }).Count; commandsTotal = $Script:Sandbox.Commands.Count } } else { [ordered]@{ exists = $false } }
    return [ordered]@{
        version = $Script:ServerInfo.version; machine = $env:COMPUTERNAME; time = (Get-Date).ToString('o')
        startup = $Script:Counters.startup; gateway = $Script:GatewayState
        mcp = [ordered]@{ prefix = $Script:McpPrefix; allowedIps = $Script:Config.AllowedIps; token = (-not [string]::IsNullOrEmpty($Script:Config.Token)) }
        vcenters = $vcenters; sbx = $sbx; counters = $Script:Counters
        tools = @($Script:Catalog.Name); policy = $Script:PolicyMeta
        export = [ordered]@{ active = $Script:ExportState.active; sent = $Script:ExportState.sent; failures = $Script:ExportState.failures; pending = $Script:ExportState.pending; spool = $Script:ExportState.spool; lastError = $Script:ExportState.lastError; lastSend = $Script:ExportState.lastSend }
        suspendedAgents = @($Script:SuspendedAgents.Keys)
        sessionsMcp = @($Script:Sessions.Values | Where-Object { $_.Creation -gt (Get-Date).AddHours(-1) }).Count
        inventory = (Get-InventoryState)
        ruleFlags = $Script:RuleFlags
        sentinel = [ordered]@{ protection = $Script:Sentinel.protection; levels = @($Script:Sentinel.agents.Values | Group-Object { $_.level } | ForEach-Object { [ordered]@{ level = $_.Name; quantity = $_.Count } }) }
    }
}

function Get-AgentList {
    $declares = @($Script:Policy.Rules | ForEach-Object { $_.Subjects.Agents } | Where-Object { $_ -and $_ -ne '*' -and $_ -notmatch '[*?]' })
    $chatPatterns = @(if ($Script:Config.Console.ContainsKey('ChatClientPatterns')) { @($Script:Config.Console.ChatClientPatterns) } else { @('*webui*', '*llama*', '*chat*', '*open-webui*', '*librechat*') })
    $ips = @($declares) + @($Script:AgentCounters.Keys) + @($Script:SuspendedAgents.Keys) | Select-Object -Unique
    $list = foreach ($ip in $ips) {
        $subject = @{ IP = $ip; Account = ''; Groups = @() }
        $rules = @(Get-ApplicableRules -Subject $subject)
        $c = if ($Script:AgentCounters.ContainsKey($ip)) { $Script:AgentCounters[$ip] } else { [ordered]@{ calls = 0; denial = 0; errors = 0; firstContact = ''; lastContact = ''; lastTool = '' } }
        $client = if ($c.Contains('client')) { [string]$c['client'] } else { '' }
        $type = if ($client -and (Test-PatternList -Value $client -Patterns $chatPatterns)) { 'discussion' } else { 'agentic' }
        [ordered]@{
            ip = $ip; declare = ($ip -in $declares); client = $client; type = $type
            user = if ($c.Contains('user')) { [string]$c['user'] } else { '' }
            users = if ($c.Contains('users')) { @($c['users']) } else { @() }
            sentinel = if ($Script:Sentinel.agents.ContainsKey($ip)) { $sa = Get-SentinelAgentState -IP $ip; [ordered]@{ level = $sa.level; score = [math]::Round($sa.score, 1); confidence = [math]::Round($sa.confidence) } } else { $null }
            rules = @($rules | ForEach-Object { [ordered]@{ id = $_.Id; name = $_.Name; effect = $_.Effect; quotaRemaining = (Get-RuleQuotaRemaining -Rule $_ -IP $ip) } })
            vcenters = (Get-AllowedVCenters -IPSource $ip)
            calls = $c.calls; denial = $c.denial; errors = $c.errors; firstContact = $c.firstContact; lastContact = $c.lastContact; lastTool = $c.lastTool
            suspended = $Script:SuspendedAgents.ContainsKey($ip); suspension = if ($Script:SuspendedAgents.ContainsKey($ip)) { $Script:SuspendedAgents[$ip] } else { $null }
        }
    }
    return [ordered]@{ agents = @($list | Sort-Object { $_.lastContact } -Descending) }
}

function Save-PolicyModified {
    <# Applies a transformation to a copy of the active policy and saves it as a new version. #>
    param([Parameter(Mandatory)][scriptblock]$Modification, [Parameter(Mandatory)][string]$Author, [Parameter(Mandatory)][string]$Comment)
    $copy = ConvertTo-DeepHashtable -Object $Script:Policy
    & $Modification $copy
    return (Save-PolicyVersion -Policy $copy -Author $Author -Comment $Comment)
}

function ConvertTo-JournalCsv {
    param([array]$LogEvents)
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add('seq;timestamp;level;agent;message;data')
    foreach ($e in $LogEvents) {
        $d = ($e.data | ConvertTo-Json -Compress -Depth 5).Replace('"', '""')
        $lines.Add(('{0};{1};{2};{3};"{4}";"{5}"' -f $e.seq, $e.timestamp, $e.level, $e.agent, $e.message.Replace('"', '""'), $d))
    }
    return ($lines -join "`r`n")
}

function Send-IconFile {
    <# V4.8.2 : serves an image from the icon subfolder. Strictly controlled name (no path, image extensions
       only), file read from that folder alone: no other file on the server is reachable. #>
    param([System.Net.HttpListenerResponse]$Response, [string]$Name)
    $types = @{ '.png' = 'image/png'; '.ico' = 'image/x-icon' }
    $extension = [System.IO.Path]::GetExtension($Name).ToLowerInvariant()
    $folder = Join-Path $Script:RootPath 'icon'
    $path = Join-Path $folder $Name
    if ($Name -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$' -or -not $types.ContainsKey($extension) -or -not (Test-Path -LiteralPath $path -PathType Leaf)) {
        Send-Body -Response $Response -Status 404 -Body '{"error":"unknown"}'; return
    }
    try {
        $bytes = [System.IO.File]::ReadAllBytes($path)
        $Response.StatusCode = 200
        $Response.ContentType = $types[$extension]
        $Response.Headers['Cache-Control'] = 'private, max-age=3600'
        $Response.ContentLength64 = $bytes.Length
        $Response.OutputStream.Write($bytes, 0, $bytes.Length)
        $Response.OutputStream.Close()
    }
    catch {
        if (-not (Test-ClientDisconnected -Error $_.Exception)) { throw }
        try { $Response.Abort() } catch { }
    }
}

function Invoke-ConsoleRequest {
    param([System.Net.HttpListenerContext]$Context)
    $request = $Context.Request; $response = $Context.Response
    $path = $request.Url.AbsolutePath.TrimEnd('/'); if ($path -eq '') { $path = '/' }
    $response.Headers['Cache-Control'] = 'no-store'
    $response.Headers['X-Content-Type-Options'] = 'nosniff'
    $response.Headers['X-Frame-Options'] = 'DENY'
    try {
        $access = Test-ConsoleAccess -Context $Context
        if (-not $access.Ok) {
            Write-Journal -Level 'DENIED' -Message "Console: access denied ($($access.Reason))" -Data @{ ip = (Get-RequestIp -Request $request); user = $access.Name }
            Send-Body -Response $response -Status 403 -Body '{"error":"access denied"}'; return
        }
        $author = $access.Name
        $q = $request.QueryString
        $method = $request.HttpMethod

        if ($path -eq '/' -and $method -eq 'GET') { Send-Body -Response $response -Status 200 -Body $Script:PageConsole -ContentType 'text/html; charset=utf-8'; return }

        if ($path -like '/icon/*' -and $method -eq 'GET') { Send-IconFile -Response $response -Name $path.Substring(7); return }
        if ($path -notlike '/api/*') { Send-Body -Response $response -Status 404 -Body '{"error":"unknown"}'; return }
        # V4.6 : anti-CSRF. The console uses Windows integrated authentication (the browser sends credentials
        # automatically): a POST triggered by another site would use those credentials. We therefore require that the origin,
        # when the browser sends it, matches the console host itself (same origin).
        if ($method -in @('POST', 'DELETE', 'PUT')) {
            $origin = $request.Headers['Origin']
            if (-not [string]::IsNullOrEmpty($origin)) {
                $originHost = ''
                try { $originHost = ([uri]$origin).Authority } catch { }
                if ($originHost -ne $request.UserHostName) {
                    Write-Journal -Level 'DENIED' -Message "Console: origin denied (CSRF): $origin" -Data @{ ip = (Get-RequestIp -Request $request); user = $author; origin = $origin }
                    Send-Body -Response $response -Status 403 -Body '{"error":"origin denied"}'; return
                }
            }
        }
        $body = if ($method -eq 'POST') { Read-JsonBody -Request $request } else { @{} }
        $result = $null

        switch -Regex ("$method $path") {
            '^GET /api/state$'     { $result = Get-GlobalState; $result.user = $author }
            '^GET /api/agents$'   { $result = Get-AgentList }
            '^POST /api/agents/suspend$' {
                $ip = [string]$body.ip; if (-not $ip) { throw 'ip missing' }
                $Script:SuspendedAgents[$ip] = [ordered]@{ by = $author; since = (Get-Date).ToString('o'); reason = [string]$body.reason }
                Write-Journal -Level 'ADMIN' -Message "Agent suspended: $ip" -Data @{ author = $author; agent = $ip; reason = [string]$body.reason }
                $result = @{ ok = $true }
            }
            '^POST /api/agents/resume$' {
                $ip = [string]$body.ip
                if ($Script:Sentinel.agents.ContainsKey($ip) -and $Script:Sentinel.agents[$ip].quarantine) { Clear-AgentQuarantine -IP $ip -Author $author }
                $Script:SuspendedAgents.Remove($ip)
                Write-Journal -Level 'ADMIN' -Message "Agent resumed: $ip" -Data @{ author = $author; agent = $ip }
                $result = @{ ok = $true }
            }
            '^POST /api/gateway/suspend$' {
                $Script:GatewayState.suspended = $true; $Script:GatewayState.reason = [string]$body.reason; $Script:GatewayState.by = $author; $Script:GatewayState.since = (Get-Date).ToString('o')
                Write-Journal -Level 'ADMIN' -Message 'Gateway suspended' -Data @{ author = $author; reason = [string]$body.reason }
                $result = @{ ok = $true }
            }
            '^POST /api/gateway/resume$' {
                $Script:GatewayState.suspended = $false; $Script:GatewayState.reason = ''; $Script:GatewayState.by = ''; $Script:GatewayState.since = ''
                Write-Journal -Level 'ADMIN' -Message 'Gateway resumed' -Data @{ author = $author }
                $result = @{ ok = $true }
            }
            '^GET /api/policy$'          { $result = [ordered]@{ meta = $Script:PolicyMeta; policy = $Script:Policy } }
            '^GET /api/policy/versions$' { $result = @{ versions = @(Get-PolicyVersions) } }
            '^GET /api/policy/versions/(\d+)$' {
                $n = [int]$Matches[1]
                $f = Join-Path (Join-Path $Script:PoliciesPath 'history') ("v{0:D5}.json" -f $n)
                if (-not (Test-Path $f)) { throw "version $n not found" }
                $result = Read-PolicyFile -Path $f
            }
            '^POST /api/policy$' {
                if (-not $body.ContainsKey('policy')) { throw 'policy field missing' }
                $meta = Save-PolicyVersion -Policy ([hashtable]$body.policy) -Author $author -Comment ([string]$body.comment)
                Write-Journal -Level 'ADMIN' -Message "New policy v$($meta.version) (full edit)" -Data @{ author = $author; version = $meta.version; comment = $meta.comment; sha256 = $meta.sha256 }
                $result = @{ ok = $true; meta = $meta }
            }
            '^POST /api/policy/restore$' {
                $n = [int]$body.version
                $meta = Restore-PolicyVersion -Version $n -Author $author
                Write-Journal -Level 'ADMIN' -Message "Policy restored from v$n (new v$($meta.version))" -Data @{ author = $author; version = $meta.version; source = $n }
                $result = @{ ok = $true; meta = $meta }
            }
            # ----- Rules -----
            '^GET /api/rules$' {
                $result = [ordered]@{
                    rules = @(Get-RulesView); groups = $Script:Policy.CommandGroups; scopes = $Script:Policy.Scopes
                    implicitScopes = @($Script:VcenterConnections.Keys | ForEach-Object { "vc:$_" }); vcenters = @($Script:VcenterConnections.Keys)
                    nonPowerCliTools = $Script:NonPowerCliTools; meta = $Script:PolicyMeta; flags = $Script:RuleFlags
                }
            }
            '^POST /api/rules$' {
                $rule = [hashtable]$body.rule; if (-not $rule) { throw 'rule field missing' }
                if (-not $rule.ContainsKey('Id') -or [string]::IsNullOrWhiteSpace([string]$rule.Id)) { $rule.Id = ((([string]$rule.Name) -replace '[^A-Za-z0-9]+', '-').Trim('-').ToLowerInvariant() + '-' + (Get-Date -Format 'yyMMddHHmm')) }
                $exists = [bool]($Script:Policy.Rules | Where-Object { $_.Id -eq $rule.Id })
                $meta = Save-PolicyModified -Author $author -Comment "Rule '$($rule.Name)' $(if ($exists) { 'modified' } else { 'created' })" -Modification {
                    param($p)
                    $p.Rules = @(@($p.Rules | Where-Object { $_.Id -ne $rule.Id }) + @($rule))
                }
                Write-Journal -Level 'ADMIN' -Message "Rule $(if ($exists) { 'modified' } else { 'created' }): $($rule.Id)" -Data @{ author = $author; rule = $rule.Id; version = $meta.version }
                $result = @{ ok = $true; meta = $meta; id = $rule.Id }
            }
            '^POST /api/rules/state$' {
                $id = [string]$body.id; $state = [string]$body.state
                if ($state -notin @('active', 'inactive')) { throw 'state must be active or inactive' }
                $meta = Save-PolicyModified -Author $author -Comment "Rule '$id' set to $state" -Modification { param($p) $r = $p.Rules | Where-Object { $_.Id -eq $id }; if (-not $r) { throw "unknown rule: $id" }; $r.State = $state }
                Write-Journal -Level 'ADMIN' -Message "Rule $id : $state" -Data @{ author = $author; rule = $id; version = $meta.version }
                $result = @{ ok = $true; meta = $meta }
            }
            '^POST /api/rules/flags$' {
                $id = [string]$body.id; $flags = @($body.flags | ForEach-Object { [string]$_ })
                $meta = Save-PolicyModified -Author $author -Comment "Flags of rule '$id': $(if ($flags.Count) { $flags -join ', ' } else { 'none' })" -Modification { param($p) $r = $p.Rules | Where-Object { $_.Id -eq $id }; if (-not $r) { throw "unknown rule: $id" }; $r.Flags = $flags }
                Write-Journal -Level 'ADMIN' -Message "Flags of rule $id modified" -Data @{ author = $author; rule = $id; flags = $flags; version = $meta.version }
                $result = @{ ok = $true; meta = $meta }
            }
            '^POST /api/rules/suspend$' {
                $id = [string]$body.id
                if (-not ($Script:Policy.Rules | Where-Object { $_.Id -eq $id })) { throw "unknown rule: $id" }
                $Script:RulesState.suspended[$id] = [ordered]@{ by = $author; since = (Get-Date).ToString('o'); reason = [string]$body.reason }
                Save-RulesState
                Write-Journal -Level 'ADMIN' -Message "Rule suspended: $id" -Data @{ author = $author; rule = $id; reason = [string]$body.reason }
                $result = @{ ok = $true }
            }
            '^POST /api/rules/resume$' {
                $id = [string]$body.id; $Script:RulesState.suspended.Remove($id); Save-RulesState
                Write-Journal -Level 'ADMIN' -Message "Rule resumed: $id" -Data @{ author = $author; rule = $id }
                $result = @{ ok = $true }
            }
            '^POST /api/rules/reset-usage$' {
                $id = [string]$body.id; $Script:RulesState.usages.Remove($id); Save-RulesState
                Write-Journal -Level 'ADMIN' -Message "Rule usage reset: $id" -Data @{ author = $author; rule = $id }
                $result = @{ ok = $true }
            }
            '^POST /api/rules/remove$' {
                $id = [string]$body.id
                $meta = Save-PolicyModified -Author $author -Comment "Rule '$id' deleted" -Modification { param($p) if (-not ($p.Rules | Where-Object { $_.Id -eq $id })) { throw "unknown rule: $id" }; $p.Rules = @($p.Rules | Where-Object { $_.Id -ne $id }) }
                Write-Journal -Level 'ADMIN' -Message "Rule deleted: $id" -Data @{ author = $author; rule = $id; version = $meta.version }
                $result = @{ ok = $true; meta = $meta }
            }
            # ----- Command groups and scopes -----
            '^POST /api/groups$' {
                $name = [string]$body.name; $cmdlets = $body.cmdlets; $description = [string]$body.description
                $meta = Save-PolicyModified -Author $author -Comment "Command group '$name' saved" -Modification { param($p) $p.CommandGroups[$name] = @{ Description = $description; Cmdlets = $cmdlets } }
                Write-Journal -Level 'ADMIN' -Message "Command group saved: $name" -Data @{ author = $author; group = $name; version = $meta.version }
                $result = @{ ok = $true; meta = $meta }
            }
            '^POST /api/groups/remove$' {
                $name = [string]$body.name
                $meta = Save-PolicyModified -Author $author -Comment "Command group '$name' deleted" -Modification { param($p) $p.CommandGroups.Remove($name) }
                Write-Journal -Level 'ADMIN' -Message "Command group deleted: $name" -Data @{ author = $author; group = $name; version = $meta.version }
                $result = @{ ok = $true; meta = $meta }
            }
            '^POST /api/scopes$' {
                $name = [string]$body.name; $description = [string]$body['description']
                $per = @{ Description = $description; VCenters = $body['vcenters']; Tags = $body['tags']; Clusters = $body['clusters']; Folders = $body['folders']; VmPatterns = $body['vmPatterns']; InfraVisible = [bool]$body['infraVisible'] }
                $meta = Save-PolicyModified -Author $author -Comment "Scope '$name' saved" -Modification { param($p) $p.Scopes[$name] = $per }
                Write-Journal -Level 'ADMIN' -Message "Scope saved: $name" -Data @{ author = $author; scope = $name; version = $meta.version }
                $result = @{ ok = $true; meta = $meta }
            }
            '^POST /api/scopes/preview$' {
                $per = @{ VCenters = @(ConvertTo-TextList $body['vcenters']); Tags = @(ConvertTo-TextList $body['tags']); Clusters = @(ConvertTo-TextList $body['clusters']); Folders = @(ConvertTo-TextList $body['folders']); VmPatterns = @(ConvertTo-TextList $body['vmPatterns']); InfraVisible = [bool]$body['infraVisible'] }
                $result = Get-ScopePreview -Scope $per
            }
            '^POST /api/scopes/remove$' {
                $name = [string]$body.name
                $meta = Save-PolicyModified -Author $author -Comment "Scope '$name' deleted" -Modification { param($p) $p.Scopes.Remove($name) }
                Write-Journal -Level 'ADMIN' -Message "Scope deleted: $name" -Data @{ author = $author; scope = $name; version = $meta.version }
                $result = @{ ok = $true; meta = $meta }
            }
            '^POST /api/settings$' {
                $global = [hashtable]$body.global
                $meta = Save-PolicyModified -Author $author -Comment 'Global settings modified' -Modification { param($p) foreach ($key in $global.Keys) { $p.Global[$key] = $global[$key] } }
                Write-Journal -Level 'ADMIN' -Message 'Global settings modified' -Data @{ author = $author; version = $meta.version; keyNames = @($global.Keys) }
                $result = @{ ok = $true; meta = $meta }
            }
            '^POST /api/simulate$' {
                $instant = if ($body.ContainsKey('instant') -and $body.instant) { ConvertTo-DateTime $body.instant } else { Get-Date }
                $result = Invoke-Simulation -IPSource ([string]$body.ip) -Line ([string]$body.line) -Tool $(if ($body.ContainsKey('tool') -and $body.tool) { [string]$body.tool } else { 'Invoke-PowerCLI' }) -Now $instant
                Write-Journal -Level 'ADMIN' -Message "Simulation: $($result.verdict)" -Data @{ author = $author; agent = [string]$body.ip; line = [string]$body.line }
            }
            '^GET /api/cmdlets$' {
                $filter = [string]$q['filter']
                $list = if ($Script:Sandbox) { @($Script:Sandbox.Commands | Where-Object { $_.ModuleName -like 'VMware.*' -and $_.CommandType -in 'Cmdlet','Function' -and $_.Name -like 'Get-*' -and (-not $filter -or $_.Name -like "*$filter*") } | ForEach-Object { $_.Name } | Sort-Object -Unique) } else { @() }
                $result = @{ cmdlets = $list }
            }
            '^GET /api/journal$' {
                $since = if ($q['since']) { [int]$q['since'] } else { 0 }
                $limit = if ($q['limit']) { [int]$q['limit'] } else { 200 }
                $evts = Get-MemoryJournal -SinceSeq $since -Level ([string]$q['level']) -Agent ([string]$q['agent']) -Text ([string]$q['text']) -Limit $limit
                $result = @{ logEvents = $evts; lastSeq = $Script:JournalSequence }
            }
            '^GET /api/journal/export$' {
                $evts = Get-MemoryJournal -Level ([string]$q['level']) -Agent ([string]$q['agent']) -Text ([string]$q['text']) -Limit $Script:JournalMaxSize
                Write-Journal -Level 'ADMIN' -Message 'Journal export from the console' -Data @{ author = $author; quantity = $evts.Count; format = [string]$q['format'] }
                if ($q['format'] -eq 'csv') {
                    $response.Headers['Content-Layout'] = 'attachment; filename="mithrandir-journal.csv"'
                    Send-Body -Response $response -Status 200 -Body (ConvertTo-JournalCsv -LogEvents $evts) -ContentType 'text/csv; charset=utf-8'
                }
                else {
                    $response.Headers['Content-Layout'] = 'attachment; filename="mithrandir-journal.jsonl"'
                    Send-Body -Response $response -Status 200 -Body (($evts | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 6 }) -join "`n") -ContentType 'application/x-ndjson; charset=utf-8'
                }
                return
            }
            '^GET /api/export$' { $result = $Script:ExportState.Clone() }
            '^POST /api/export/test$' {
                Write-Journal -Level 'ADMIN' -Message 'SIEM export test event' -Data @{ author = $author; test = $true }
                $result = @{ ok = $true; active = $Script:ExportState.active }
            }
            '^GET /api/inventory$' { $result = Get-InventoryState }
            '^GET /api/inventory/tree$' { $result = Get-InventoryTree }
            '^POST /api/inventory/refresh$' {
                if (-not $Script:Inventory.active) { throw "automatic inventory is not enabled" }
                Request-InventoryRefresh
                Write-Journal -Level 'ADMIN' -Message "Inventory refresh requested" -Data @{ author = $author }
                $result = @{ ok = $true }
            }
            '^POST /api/inventory/settings$' {
                $result = Set-InventorySettings -Settings $body -Author $author
            }
            '^GET /api/inventory/objects$' {
                # Admin preview (all vCenters): same filters as the MCP tool
                $arguments = @{}; foreach ($key in @('Type', 'Name', 'Cluster', 'Folder', 'Tag', 'PowerState', 'GroupBy', 'Limit')) { if ($q[$key]) { $arguments[$key] = [string]$q[$key] } }
                if ($q['Server']) { $arguments.Server = @(([string]$q['Server']) -split ',') }
                $result = Search-Inventory -Arguments $arguments -VCenters @($Script:VcenterConnections.Keys)
            }
            '^POST /api/scripts/analyze$' {
                $scripts = @($body.scripts | Where-Object { $_ })
                $result = Invoke-ScriptAnalysis -Scripts $scripts
                Write-Journal -Level 'ADMIN' -Message "Analysis of $($scripts.Count) script(s) for a policy" -Data @{ author = $author; scripts = @($scripts | ForEach-Object { [string]$_.name }); cmdlets = $result.resume.allowed }
            }
            '^GET /api/activity$' {
                # Logged activity of an agent, aggregated by cmdlet (basis of "from activity to a rule")
                $agent = [string]$q['agent']; if (-not $agent) { throw 'agent parameter missing' }
                $hours = if ($q['hours']) { [int]$q['hours'] } else { 168 }
                $result = Get-AgentActivity -Agent $agent -SinceHours $hours
            }
            '^GET /api/sentinel$' { $result = Get-SentinelView }
            '^POST /api/sentinel/acknowledge$' { $ip = [string]$body.ip; if (-not $ip) { throw 'ip missing' }; Clear-AgentQuarantine -IP $ip -Author $author; $result = @{ ok = $true } }
            '^POST /api/sentinel/quarantine$' {
                $ip = [string]$body.ip; if (-not $ip) { throw 'ip missing' }
                Set-AgentQuarantine -IP $ip -Reason ("manual: " + [string]$body.reason) -By $author
                $result = @{ ok = $true }
            }
            '^POST /api/sentinel/protection/lift$' { Clear-GlobalProtection -Author $author; $result = @{ ok = $true } }
            '^POST /api/sentinel/test-alert$' {
                Write-Journal -Level 'ALERT' -Message 'Sentinel: test alert' -Data @{ author = $author; test = $true }
                Send-AlertMIThrandir -Title 'MIThrandir: test alert' -Text "Test alert triggered from the console by $author." -Severity 'test'
                $result = @{ ok = $true }
            }
            '^GET /api/vcenters$' { $result = @{ vcenters = (Get-GlobalState).vcenters } }
            # ----- V4.5 : vCenter list managed from the console -----
            '^GET /api/vcenters/config$' {
                $result = Get-VcentersView
                $result.channelOn = [bool]($request.IsSecureConnection -or $request.IsLocal)
            }
            '^POST /api/vcenters/certificate$' {
                $server = ([string]$body.server).Trim(); if (-not $server) { throw 'server missing' }
                $result = Get-ConsoleCertificate -Server $server -Port $(if ($body.port) { [int]$body.port } else { 443 })
            }
            '^POST /api/vcenters/save$' {
                $result = Set-VCenterConsole -Body $body -Author $author -ChannelOn ([bool]($request.IsSecureConnection -or $request.IsLocal))
            }
            '^POST /api/vcenters/remove$' {
                $name = [string]$body.name; if (-not $name) { throw 'name missing' }
                $result = Remove-VCenterConsole -Name $name -Author $author
            }
            '^POST /api/vcenters/reconnect$' {
                $name = [string]$body.name; if (-not $Script:VcenterConnections.Contains($name)) { throw "unknown vCenter: $name" }
                Write-Journal -Level 'ADMIN' -Message "Reconnection requested: $name" -Data @{ author = $author; vcenter = $name }
                $ok = Connect-VcenterInSandbox -Name $name -AcceptAnyCertificate:$Script:AcceptAnyCertificate
                $result = @{ ok = $ok; error = $Script:VcenterConnections[$name].Error }
            }
            default { Send-Body -Response $response -Status 404 -Body '{"error":"route unknown"}'; return }
        }
        Send-Body -Response $response -Status 200 -Body ($result | ConvertTo-Json -Depth 12)
    }
    catch {
        Write-Host ("CONSOLE STACK: " + $_.ScriptStackTrace) -ForegroundColor DarkRed
        Write-Journal -Level 'ERROR' -Message "Console: $($_.Exception.Message)" -Data @{ ip = (Get-RequestIp -Request $request); route = $path; stack = ($_.ScriptStackTrace -split "`n" | Select-Object -First 3) }
        try { Send-Body -Response $response -Status 400 -Body (@{ error = $_.Exception.Message } | ConvertTo-Json) } catch { }
    }
}

# ---------------------------------------------------------------------------
# HTML page: Console.html next to the script (no external resource), re-read at each startup
# ---------------------------------------------------------------------------
$pagePath = Join-Path $Script:RootPath 'Console.html'
if (-not (Test-Path $pagePath)) { throw "Console.html not found: $pagePath" }
$Script:PageConsole = [System.IO.File]::ReadAllText($pagePath, [System.Text.Encoding]::UTF8)
