<#
.SYNOPSIS
    MIThrandir V3 log: console, JSONL file, circular memory buffer for the administration console,
    per-agent counters, and asynchronous export to Splunk HEC and/or syslog (SIEM).

.DESCRIPTION
    Write-Journal is called throughout MIThrandir. Each event:
      1. is displayed on the console and written to journal\mithrandir-YYYYMMDD.jsonl (synchronous, local)
      2. is added to a circular memory buffer (JournalMaxSize events) read by the administration console
      3. updates the global and per-agent counters
      4. is pushed to an export queue; a background runspace drains it to Splunk HEC and/or syslog,
         with retries, and a local spool (journal\spool\) if the target is unreachable. MIThrandir never blocks on export.

    Levels: INFO, CALL (call), DENIED (refusal), ERROR (error), ADMIN (actions taken from the administration console),
    ALERT (alert; sentinel: agent drift, quarantine, protection mode).
#>

$Script:MemoryJournal   = [System.Collections.Generic.List[object]]::new()
$Script:JournalMaxSize = 5000
$Script:JournalSequence  = 0
$Script:Counters        = [ordered]@{ startup = (Get-Date).ToString('o'); calls = 0; denial = 0; errors = 0; initializations = 0; admin = 0 }
$Script:AgentCounters  = @{}   # ip -> @{ calls; denial; errors; lastContact; lastTool; firstContact }
$Script:FileExport       = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
$Script:ExportState       = [hashtable]::Synchronized(@{ active = $false; sent = 0; failures = 0; pending = 0; spool = 0; lastError = ''; lastSend = '' })
$Script:RunspaceExport   = $null

function Write-Journal {
    param(
        [Parameter(Mandatory)][string]$Level,
        [Parameter(Mandatory)][string]$Message,
        [hashtable]$Data = @{}
    )
    $timestamp = (Get-Date).ToString('o')
    $color = switch ($Level) { 'ALERT' { 'Red' } 'ERROR' { 'Red' } 'DENIED' { 'Yellow' } 'CALL' { 'Cyan' } 'ADMIN' { 'Magenta' } default { 'Gray' } }
    $suffix = if ($Data.Count -gt 0) { ' ' + ($Data | ConvertTo-Json -Compress -Depth 5) } else { '' }
    Write-Host ("[{0}] [{1,-6}] {2}{3}" -f $timestamp, $Level, $Message, $suffix) -ForegroundColor $color

    $Script:JournalSequence++
    $logEvent = [ordered]@{
        seq = $Script:JournalSequence; timestamp = $timestamp; level = $Level; message = $Message
        agent = if ($Data.ContainsKey('ip')) { [string]$Data['ip'] } else { '' }
        user = if ($Data.ContainsKey('ip') -and (Get-Variable -Name CurrentIdentity -Scope Script -ErrorAction SilentlyContinue) -and $Script:CurrentIdentity.Account) { [string]$Script:CurrentIdentity.Account } else { '' }
        data = $Data
        host = $env:COMPUTERNAME; source = 'mithrandir'
    }
    $line = $logEvent | ConvertTo-Json -Compress -Depth 6

    # 1. Local file
    try {
        if (-not (Test-Path $Script:JournalPath)) { New-Item -ItemType Directory -Path $Script:JournalPath | Out-Null }
        Add-Content -Path $Script:JournalFile -Value $line -Encoding utf8
    }
    catch { Write-Host "Journal file unavailable: $($_.Exception.Message)" -ForegroundColor DarkYellow }

    # 2. Circular memory buffer
    $Script:MemoryJournal.Add($logEvent)
    if ($Script:MemoryJournal.Count -gt $Script:JournalMaxSize) { $Script:MemoryJournal.RemoveRange(0, $Script:MemoryJournal.Count - $Script:JournalMaxSize) }

    # 3. Counters
    switch ($Level) {
        'CALL'  { $Script:Counters.calls++ }
        'DENIED'  { $Script:Counters.denial++ }
        'ERROR' { $Script:Counters.errors++ }
        'ADMIN'  { $Script:Counters.admin++ }
        'ALERT' { if ($Script:Counters.Contains('alerts')) { $Script:Counters.alerts++ } else { $Script:Counters['alerts'] = 1 } }
    }
    if ($Message -eq 'initialize') { $Script:Counters.initializations++ }
    if ($logEvent.agent) {
        $ip = $logEvent.agent
        if (-not $Script:AgentCounters.ContainsKey($ip)) { $Script:AgentCounters[$ip] = [ordered]@{ calls = 0; denial = 0; errors = 0; firstContact = $timestamp; lastContact = $timestamp; lastTool = '' } }
        $c = $Script:AgentCounters[$ip]
        $c.lastContact = $timestamp
        if ($logEvent.user) {
            $c['user'] = $logEvent.user
            if (-not $c.Contains('users')) { $c['users'] = [System.Collections.Generic.List[string]]::new() }
            if (-not $c['users'].Contains($logEvent.user)) { $c['users'].Add($logEvent.user); if ($c['users'].Count -gt 20) { $c['users'].RemoveAt(0) } }
        }
        switch ($Level) {
            'CALL'  { $c.calls++; if ($Data.ContainsKey('line')) { $c.lastTool = [string]$Data['line'] } elseif ($Message -match '^Execution of (.+)$') { $c.lastTool = $Matches[1] } }
            'DENIED'  { $c.denial++ }
            'ERROR' { $c.errors++ }
        }
        if ($Message -eq 'initialize' -and $Data.ContainsKey('client') -and $Data['client']) {
            $client = $Data['client']
            $c['client'] = (("{0} {1}" -f $client['name'], $client['version']).Trim())
        }
    }

    # 4. Sentinel: every call and every refusal of an agent feeds its suspicion score
    if ($Level -in @('CALL', 'DENIED') -and $logEvent.agent -and (Get-Command -Name Register-SentinelSignal -ErrorAction SilentlyContinue)) {
        try { Register-SentinelSignal -LogEvent $logEvent } catch { Write-Host "Sentinel: $($_.Exception.Message)" -ForegroundColor DarkYellow }
    }

    # 5. Asynchronous export
    if ($Script:ExportState.active) {
        $Script:FileExport.Enqueue($line)
        $Script:ExportState.pending = $Script:FileExport.Count
    }
}

function Get-MemoryJournal {
    param([int]$SinceSeq = 0, [string]$Level = '', [string]$Agent = '', [string]$Text = '', [int]$Limit = 200)
    $result = $Script:MemoryJournal | Where-Object {
        $_.seq -gt $SinceSeq -and
        (-not $Level -or $_.level -eq $Level) -and
        (-not $Agent -or $_.agent -eq $Agent) -and
        (-not $Text -or ($_.message -like "*$Text*") -or (($_.data | ConvertTo-Json -Compress -Depth 5) -like "*$Text*"))
    }
    return @($result | Select-Object -Last $Limit)
}

# ---------------------------------------------------------------------------
# Export: Splunk HEC and syslog, in a background runspace
# ---------------------------------------------------------------------------
$Script:ScriptExport = {
    param($File, $State, $ConfigExport, $SpoolPath, $CefLevelsCard)
    $ErrorActionPreference = 'Continue'
    if (-not (Test-Path $SpoolPath)) { New-Item -ItemType Directory -Path $SpoolPath -Force | Out-Null }
    $splunk = $ConfigExport.Splunk; $syslog = $ConfigExport.Syslog
    $otlp = if ($ConfigExport.ContainsKey('Otlp')) { $ConfigExport.Otlp } else { @{ Active = $false } }
    $clientUdp = $null

    function ConvertTo-Cef {
        param($LogEvent)
        $severity = switch ($LogEvent.level) { 'ALERT' { 9 } 'ERROR' { 7 } 'DENIED' { 6 } 'ADMIN' { 5 } 'CALL' { 3 } default { 1 } }
        $sample = { param($t) ([string]$t).Replace('\', '\\').Replace('=', '\=').Replace("`n", ' ').Replace("`r", '') }
        $ext = "rt=$([DateTimeOffset]::Parse($LogEvent.timestamp).ToUnixTimeMilliseconds()) src=$($LogEvent.agent) dvchost=$($LogEvent.host) msg=$(& $sample $LogEvent.message)"
        if ($LogEvent.PSObject.Properties['user'] -and $LogEvent.user) { $ext += " suser=$(& $sample $LogEvent.user)" }
        if ($LogEvent.data) {
            $d = $LogEvent.data
            foreach ($key in @('line', 'reason', 'servers', 'cmdlets', 'author', 'version', 'durationMs')) {
                if ($d.PSObject.Properties[$key]) { $v = $d.$key; if ($v -is [array]) { $v = $v -join ',' }; $ext += " cs_$key=$(& $sample $v)" }
            }
        }
        $classified = ($LogEvent.message -replace '[^A-Za-z0-9 _:-]', '').Substring(0, [math]::Min(60, $LogEvent.message.Length))
        return "CEF:0|MIThrandir|MIThrandir|0.49.0|$($LogEvent.level)|$classified|$severity|$ext"
    }

    function Send-Syslog {
        param([string]$Charge)
        $facility = 18   # local2
        $sev = 6         # informational; the fine-grained severity is in the CEF payload
        $priority = $facility * 8 + $sev
        $header = "<$priority>1 $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')) $env:COMPUTERNAME mithrandir - - -"
        $frame = "$header $Charge"
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($frame)
        if ($syslog.Protocol -eq 'tcp') {
            $client = [System.Net.Sockets.TcpClient]::new(); $client.Connect($syslog.Host, [int]$syslog.Port)
            $stream = $client.GetStream()
            $box = [System.Text.Encoding]::UTF8.GetBytes("$($bytes.Length) ")   # octet-counting RFC 6587
            $stream.Write($box, 0, $box.Length); $stream.Write($bytes, 0, $bytes.Length); $stream.Flush(); $client.Close()
        }
        else {
            if ($null -eq $script:clientUdp) { $script:clientUdp = [System.Net.Sockets.UdpClient]::new() }
            [void]$script:clientUdp.Send($bytes, $bytes.Length, $syslog.Host, [int]$syslog.Port)
        }
    }

    function ConvertTo-Otlp {
        # OTLP/HTTP logs (JSON): one ResourceLogs, one ScopeLogs, one LogRecord per event. Format accepted by an
        # OpenTelemetry collector on /v1/logs. OTel severity: INFO 9-12, WARN 13-16, ERROR 17-20, FATAL 21-24.
        param([string[]]$Lines)
        $records = foreach ($l in $Lines) {
            $e = $l | ConvertFrom-Json
            $sevNum = switch ($e.level) { 'ALERT' { 21 } 'ERROR' { 17 } 'DENIED' { 13 } 'ADMIN' { 10 } 'CALL' { 9 } 'INFO' { 9 } default { 9 } }
            $ns = ([DateTimeOffset]::Parse($e.timestamp).ToUnixTimeMilliseconds() * 1000000).ToString()
            $attrs = [System.Collections.Generic.List[object]]::new()
            $add = { param($k, $v) if ($null -ne $v -and "$v" -ne '') { $attrs.Add(@{ key = $k; value = @{ stringValue = "$v" } }) } }
            & $add 'mithrandir.level' $e.level
            if ($e.PSObject.Properties['agent']) { & $add 'mithrandir.agent' $e.agent }
            if ($e.PSObject.Properties['user']) { & $add 'enduser.id' $e.user }
            if ($e.PSObject.Properties['data'] -and $e.data) {
                foreach ($key in @('line', 'reason', 'author', 'version', 'durationMs', 'cmdlets', 'servers')) {
                    if ($e.data.PSObject.Properties[$key]) { $val = $e.data.$key; if ($val -is [array]) { $val = $val -join ',' }; & $add "mithrandir.$key" $val }
                }
            }
            @{ timeUnixNano = $ns; observedTimeUnixNano = $ns; severityNumber = $sevNum; severityText = $e.level; body = @{ stringValue = [string]$e.message }; attributes = @($attrs) }
        }
        $resource = @{ attributes = @(
            @{ key = 'service.name';      value = @{ stringValue = 'mithrandir' } }
            @{ key = 'service.namespace'; value = @{ stringValue = 'mithrandir' } }
            @{ key = 'host.name';         value = @{ stringValue = $env:COMPUTERNAME } }
        ) }
        return @{ resourceLogs = @(@{ resource = $resource; scopeLogs = @(@{ scope = @{ name = 'mithrandir'; version = '0.49.0' }; logRecords = @($records) }) }) }
    }

    function Send-Otlp {
        param([string[]]$Lines)
        $body = ConvertTo-Otlp -Lines $Lines | ConvertTo-Json -Depth 12 -Compress
        $headers = @{}
        if ($otlp.PSObject.Properties['Headers'] -and $otlp.Headers) { foreach ($k in $otlp.Headers.Keys) { $headers[$k] = [string]$otlp.Headers[$k] } }
        $uri = ($otlp.Endpoint.TrimEnd('/')) + '/v1/logs'
        $parameters = @{ Uri = $uri; Method = 'Post'; Body = $body; ContentType = 'application/json'; TimeoutSec = 10 }
        if ($headers.Count -gt 0) { $parameters.Headers = $headers }
        if ($otlp.PSObject.Properties['IgnoreCertificate'] -and $otlp.IgnoreCertificate) { $parameters.SkipCertificateCheck = $true }
        Invoke-RestMethod @parameters | Out-Null
    }

    function Send-Lot {
        param([string[]]$Lines)
        if ($otlp -and $otlp.Active) { Send-Otlp -Lines $Lines }
        if ($splunk.Active) {
            $logEvents = foreach ($l in $Lines) { $e = $l | ConvertFrom-Json; @{ time = [DateTimeOffset]::Parse($e.timestamp).ToUnixTimeMilliseconds() / 1000; host = $e.host; source = 'mithrandir'; sourcetype = $splunk.SourceType; index = $splunk.Index; event = $e } }
            $body = ($logEvents | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 8 }) -join "`n"
            $parameters = @{ Uri = $splunk.Url; Method = 'Post'; Body = $body; ContentType = 'application/json'; Headers = @{ Authorization = "Splunk $($splunk.Token)" }; TimeoutSec = 10 }
            if ($splunk.IgnoreCertificate) { $parameters.SkipCertificateCheck = $true }
            Invoke-RestMethod @parameters | Out-Null
        }
        if ($syslog.Active) {
            foreach ($l in $Lines) {
                $charge = if ($syslog.Format -eq 'cef') { ConvertTo-Cef -LogEvent ($l | ConvertFrom-Json) } else { $l }
                Send-Syslog -Charge $charge
            }
        }
    }

    while ($State.active) {
        try {
            # Replay the spool first
            $spoolFiles = @(Get-ChildItem -Path $SpoolPath -Filter '*.jsonl' -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -First 5)
            foreach ($f in $spoolFiles) {
                $lines = @(Get-Content -Path $f.FullName -Encoding utf8 | Where-Object { $_ })
                if ($lines.Count -gt 0) { Send-Lot -Lines $lines; $State.sent += $lines.Count }
                Remove-Item -Path $f.FullName -Force
                $State.spool = @(Get-ChildItem -Path $SpoolPath -Filter '*.jsonl' -ErrorAction SilentlyContinue).Count
            }
            # Then the current queue, in batches
            $lot = [System.Collections.Generic.List[string]]::new()
            $line = $null
            while ($lot.Count -lt 100 -and $File.TryDequeue([ref]$line)) { $lot.Add($line) }
            $State.pending = $File.Count
            if ($lot.Count -gt 0) {
                try { Send-Lot -Lines $lot.ToArray(); $State.sent += $lot.Count; $State.lastSend = (Get-Date).ToString('o'); $State.lastError = '' }
                catch {
                    $State.failures += $lot.Count; $State.lastError = $_.Exception.Message
                    $spoolName = Join-Path $SpoolPath ("spool-{0}.jsonl" -f (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
                    [System.IO.File]::WriteAllLines($spoolName, $lot.ToArray(), [System.Text.UTF8Encoding]::new($false))
                    $State.spool = @(Get-ChildItem -Path $SpoolPath -Filter '*.jsonl' -ErrorAction SilentlyContinue).Count
                    Start-Sleep -Seconds 15
                }
            }
            else { Start-Sleep -Milliseconds 500 }
        }
        catch { $State.lastError = $_.Exception.Message; Start-Sleep -Seconds 5 }
    }
    if ($script:clientUdp) { $script:clientUdp.Dispose() }
}

function Start-ExportJournal {
    $configExport = if ($Script:Config.ContainsKey('Export')) { $Script:Config.Export } else { @{} }
    $splunk = if ($configExport.ContainsKey('Splunk')) { $configExport.Splunk } else { @{ Active = $false } }
    $syslog = if ($configExport.ContainsKey('Syslog')) { $configExport.Syslog } else { @{ Active = $false } }
    $otlp   = if ($configExport.ContainsKey('Otlp'))   { $configExport.Otlp }   else { @{ Active = $false } }
    if (-not $splunk.Active -and -not $syslog.Active -and -not $otlp.Active) { Write-Journal -Level 'INFO' -Message 'Journal export disabled (no Splunk, syslog or OTLP enabled in the configuration)'; return }
    if ($otlp.Active -and -not $otlp.ContainsKey('Endpoint')) { throw "Export.Otlp: key 'Endpoint' missing (e.g. http://otel-collector:4318)" }
    foreach ($key in @('Url', 'Token')) { if ($splunk.Active -and -not $splunk.ContainsKey($key)) { throw "Export.Splunk: key '$key' missing" } }
    foreach ($key in @('Host', 'Port')) { if ($syslog.Active -and -not $syslog.ContainsKey($key)) { throw "Export.Syslog: key '$key' missing" } }
    if ($splunk.Active -and -not $splunk.ContainsKey('SourceType')) { $splunk.SourceType = 'mithrandir:json' }
    if ($splunk.Active -and -not $splunk.ContainsKey('Index')) { $splunk.Index = 'main' }
    if ($splunk.Active -and -not $splunk.ContainsKey('IgnoreCertificate')) { $splunk.IgnoreCertificate = $false }
    if ($syslog.Active -and -not $syslog.ContainsKey('Protocol')) { $syslog.Protocol = 'udp' }
    if ($syslog.Active -and -not $syslog.ContainsKey('Format')) { $syslog.Format = 'cef' }

    $Script:ExportState.active = $true
    $spoolPath = Join-Path $Script:JournalPath 'spool'
    $Script:RunspaceExport = [PowerShell]::Create()
    [void]$Script:RunspaceExport.AddScript($Script:ScriptExport).AddArgument($Script:FileExport).AddArgument($Script:ExportState).AddArgument(@{ Splunk = $splunk; Syslog = $syslog; Otlp = $otlp }).AddArgument($spoolPath).AddArgument(@{})
    $Script:RunspaceExport.BeginInvoke() | Out-Null
    Write-Journal -Level 'INFO' -Message 'Journal export started' -Data @{ splunk = [bool]$splunk.Active; syslog = [bool]$syslog.Active; otlp = [bool]$otlp.Active; otlpEndpoint = $(if ($otlp.Active) { $otlp.Endpoint } else { '' }); syslogFormat = $syslog.Format; syslogProtocol = $syslog.Protocol }
}

function Stop-ExportJournal {
    if ($Script:RunspaceExport) {
        $Script:ExportState.active = $false
        Start-Sleep -Milliseconds 800
        try { $Script:RunspaceExport.Stop(); $Script:RunspaceExport.Dispose() } catch { }
    }
}

function Get-OpenMetricsMetrics {
    <#
    V4.6: exposes MIThrandir's state in OpenMetrics format (Prometheus-compatible, and scrapable by an OpenTelemetry
    collector through its prometheus receiver). Plain text, no dependency. Read-only.
    #>
    $lines = [System.Collections.Generic.List[string]]::new()
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    function Sample([string]$v) { return ([string]$v).Replace('\', '\\').Replace('"', '\"').Replace("`n", ' ') }
    $metric = {
        param($name, $type, $help, $value, $labels)
        $lines.Add("# HELP $name $help"); $lines.Add("# TYPE $name $type")
        $suffix = if ($labels) { '{' + (($labels.GetEnumerator() | ForEach-Object { "$($_.Key)=`"$(Sample $_.Value)`"" }) -join ',') + '}' } else { '' }
        $lines.Add("$name$suffix $value")
    }
    $version = if ((Get-Variable -Name ServerInfo -Scope Script -ErrorAction SilentlyContinue) -and $Script:ServerInfo.version) { $Script:ServerInfo.version } else { '0.49.0' }
    & $metric 'mithrandir_up' 'gauge' 'MIThrandir listening' 1 $null
    & $metric 'mithrandir_build_info' 'gauge' 'Version information' 1 ([ordered]@{ version = $version; host = $env:COMPUTERNAME })
    $c = $Script:Counters
    & $metric 'mithrandir_calls_total' 'counter' 'PowerCLI calls executed' ([int]$c.calls) $null
    & $metric 'mithrandir_denial_total' 'counter' 'Calls denied by the policy or validation' ([int]$c.denial) $null
    & $metric 'mithrandir_errors_total' 'counter' 'Execution errors' ([int]$c.errors) $null
    & $metric 'mithrandir_admin_total' 'counter' 'Administrative actions (console)' ([int]$c.admin) $null
    & $metric 'mithrandir_initializations_total' 'counter' 'MCP handshakes (initialize)' ([int]$c.initializations) $null
    & $metric 'mithrandir_alerts_total' 'counter' 'Sentinel alerts' ([int]$(if ($c.Contains('alerts')) { $c.alerts } else { 0 })) $null
    & $metric 'mithrandir_agents' 'gauge' 'Known agents (distinct IPs seen)' (@($Script:AgentCounters.Keys).Count) $null

    if (Get-Variable -Name GatewayState -Scope Script -ErrorAction SilentlyContinue) {
        & $metric 'mithrandir_gateway_suspended' 'gauge' '1 if the gateway is suspended' ([int][bool]$Script:GatewayState.suspended) $null
    }
    if (Get-Variable -Name SuspendedAgents -Scope Script -ErrorAction SilentlyContinue) {
        & $metric 'mithrandir_agents_suspended' 'gauge' 'Agents suspended' (@($Script:SuspendedAgents.Keys).Count) $null
    }

    $ex = $Script:ExportState
    & $metric 'mithrandir_export_sent_total' 'counter' 'Events exported to security (Splunk/syslog/OTLP)' ([int]$ex.sent) $null
    & $metric 'mithrandir_export_failures_total' 'counter' 'Failed export batches' ([int]$ex.failures) $null
    & $metric 'mithrandir_export_en_waiting' 'gauge' 'Events in the export queue' ([int]$ex.pending) $null
    & $metric 'mithrandir_export_spool' 'gauge' 'Export spool files awaiting replay' ([int]$ex.spool) $null

    # Inventory: freshness and VM count per vCenter
    if ((Get-Variable -Name Inventory -Scope Script -ErrorAction SilentlyContinue) -and $Script:Inventory.vcenters) {
        $firstAge = $true; $firstVms = $true
        foreach ($name in @($Script:Inventory.vcenters.Keys)) {
            $e = $Script:Inventory.vcenters[$name]; if (-not $e) { continue }
            $age = if ($e.timestamp) { [int]($now - [DateTimeOffset]::Parse($e.timestamp).ToUnixTimeSeconds()) } else { -1 }
            if ($firstAge) { $lines.Add('# HELP mithrandir_inventory_age_seconds Age of the last inventory snapshot'); $lines.Add('# TYPE mithrandir_inventory_age_seconds gauge'); $firstAge = $false }
            $lines.Add("mithrandir_inventory_age_seconds{vcenter=`"$(Sample $name)`"} $age")
            if ($firstVms) { $lines.Add('# HELP mithrandir_inventory_vms Number of VMs in the cache'); $lines.Add('# TYPE mithrandir_inventory_vms gauge'); $firstVms = $false }
            $lines.Add("mithrandir_inventory_vms{vcenter=`"$(Sample $name)`"} $(@($e.vms).Count)")
        }
    }

    # Sentinel: suspicion score per agent, protection mode
    if (Get-Command -Name Get-SentinelView -ErrorAction SilentlyContinue) {
        try {
            $view = Get-SentinelView
            if ($view.protection) { & $metric 'mithrandir_sentinel_protection' 'gauge' 'Sentinel protection mode' ([int][bool]$view.protection.active) $null }
            if ($view.agents) {
                $lines.Add('# HELP mithrandir_sentinel_suspicion Suspicion score per agent (0 to 100)'); $lines.Add('# TYPE mithrandir_sentinel_suspicion gauge')
                foreach ($a in @($view.agents)) { if ($a.ip) { $lines.Add("mithrandir_sentinel_suspicion{agent=`"$(Sample $a.ip)`"} $([int]$a.score)") } }
            }
        } catch { }
    }
    return (($lines -join "`n") + "`n# EOF`n")
}

function Get-RequestIp {
    <# Source address of an HTTP request; RemoteEndPoint is null if the client has already closed the connection. #>
    param($Request)
    try { $point = $Request.RemoteEndPoint; if ($point -and $point.Address) { return $point.Address.ToString() } } catch { }
    return 'unknown'
}

function Get-LineCommandNames {
    <# Command names (cmdlets) of a PowerCLI line, by plain syntactic parsing (never executed).
       Used to extract the cmdlets of a REFUSED line, which has no 'cmdlets' field in the log. #>
    param([string]$Line)
    if ([string]::IsNullOrWhiteSpace($Line)) { return @() }
    $names = [System.Collections.Generic.List[string]]::new()
    try {
        $tokens = $null; $errors = $null
        $tree = [System.Management.Automation.Language.Parser]::ParseInput($Line, [ref]$tokens, [ref]$errors)
        foreach ($call in @($tree.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true))) {
            $rawName = $call.GetCommandName()
            if (-not $rawName) { continue }
            $info = Get-ScriptCommandInfo -Name $rawName
            $names.Add($(if ($info) { $info.Name } else { $rawName }))
        }
    } catch { }
    return @($names | Select-Object -Unique)
}

function Get-AgentActivity {
    <#
    Aggregates an agent's logged activity per cmdlet: what it executed (CALL) and tried unsuccessfully (DENIED),
    with occurrences, vCenters seen, last use, status (global allow list) and coverage (rule that already allows it).
    Basis of the "from activity to a rule" screen (console). Reads only the in-memory log, nothing is executed.
    #>
    param([Parameter(Mandatory)][string]$Agent, [int]$SinceHours = 168)
    $g = Get-Global
    $threshold = (Get-Date).AddHours(-[math]::Abs($SinceHours))
    $subject = try { New-MIThrandirSubject -IP $Agent } catch { @{ IP = $Agent; Account = ''; Groups = @() } }

    $evts = @(Get-MemoryJournal -Agent $Agent -Limit 100000 | Where-Object {
        $_.level -in @('CALL', 'DENIED') -and ([datetime]::Parse($_.timestamp) -ge $threshold)
    })

    $byCmdlet = @{}   # name -> record
    foreach ($e in $evts) {
        $d = $e.data
        $passed = $e.level -eq 'CALL'
        # cmdlets: direct field (PowerCLI CALL), otherwise extracted from the line, otherwise the tool name from the message
        $cmds = @()
        if ($d -and $d.PSObject.Properties.Name -contains 'cmdlets' -and $d.cmdlets) { $cmds = @($d.cmdlets) }
        elseif ($d -and $d.PSObject.Properties.Name -contains 'line' -and $d.line) { $cmds = @(Get-LineCommandNames -Line ([string]$d.line)) }
        if ($cmds.Count -eq 0) { continue }   # events with no identifiable command (e.g. origin refusals): ignored here
        $vcs = if ($d -and $d.PSObject.Properties.Name -contains 'servers' -and $d.servers) { @($d.servers) } else { @() }

        foreach ($name in $cmds) {
            if (-not $byCmdlet.ContainsKey($name)) {
                # status against the global allow list (same logic as script analysis)
                $info = Get-ScriptCommandInfo -Name $name
                $module = if ($info -and $info.ModuleName) { [string]$info.ModuleName } else { '' }
                $status =
                    if ($name -in $Script:ViConnectionCommands) { 'connection' }
                    elseif ($name -in $g.Utilities) { 'utility' }
                    elseif ($name -in $Script:NonPowerCliTools -or $name -eq 'Invoke-PowerCLI') { 'tool' }
                    elseif (-not $info) { 'unknown' }
                    elseif ($module -like 'VMware.*') {
                        if ($name -in $g.ExcludedCmdlets) { 'excluded' }
                        elseif (-not (Test-PatternList -Value $name -Patterns $g.AllowedCmdlets)) { if ($name -like 'Get-*') { 'excluded' } else { 'write' } }
                        else { 'isAllowed' }
                    }
                    else { 'outside-powercli' }
                # coverage: does an Allow (allow) rule applicable to this agent already cover this cmdlet?
                $covered = ''
                try {
                    $coveringRule = @(Get-ApplicableRules -Subject $subject | Where-Object { $_.Effect -eq 'Allow' -and (Test-RuleCovers -Rule $_ -Command $name) }) | Select-Object -First 1
                    if ($coveringRule) { $covered = $coveringRule.Id }
                } catch { }
                $byCmdlet[$name] = [ordered]@{
                    cmdlet = $name; status = $status; covered = $covered
                    passed = 0; denied = 0; occurrences = 0
                    vcenters = [System.Collections.Generic.List[string]]::new()
                    last = $e.timestamp
                }
            }
            $sheet = $byCmdlet[$name]
            $sheet.occurrences++
            if ($passed) { $sheet.passed++ } else { $sheet.denied++ }
            foreach ($v in $vcs) { if ($v -and -not $sheet.vcenters.Contains([string]$v)) { $sheet.vcenters.Add([string]$v) } }
            if ([datetime]::Parse($e.timestamp) -gt [datetime]::Parse($sheet.last)) { $sheet.last = $e.timestamp }
        }
    }

    # dominant outcome per cmdlet (for display): passed if at least one success, otherwise denied
    $list = @($byCmdlet.Values | ForEach-Object {
        $_.issue = if ($_.passed -gt 0) { 'passed' } else { 'denied' }
        $_.vcenters = @($_.vcenters)
        $_
    } | Sort-Object { -$_.occurrences })

    [ordered]@{
        agent = $Agent
        sinceHours = $SinceHours
        cmdlets = $list
        resume = [ordered]@{
            distinct = $list.Count
            successful = @($list | Where-Object { $_.issue -eq 'passed' }).Count
            denied = @($list | Where-Object { $_.issue -eq 'denied' }).Count
            deniedUncovered = @($list | Where-Object { $_.issue -eq 'denied' -and -not $_.covered -and $_.status -eq 'isAllowed' }).Count
        }
    }
}
