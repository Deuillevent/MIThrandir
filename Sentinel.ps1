<#
.SYNOPSIS
    MIThrandir V4.2 Sentinel: agent drift detection and automatic protection.

.DESCRIPTION
    Each agent (currently identified by its IP) carries two indicators:
      - SUSPICION score (0 to 100): each refusal adds a weight according to its NATURE (a circumvention attempt
        weighs far more than a syntax error, which a model makes in good faith), multiplied on repeated attempts;
        the score decays on its own (configurable half-life), so an isolated slip fades away.
      - GOOD USAGE index (0 to 100): rises with successful calls, falls with refusals.
    Levels (thresholds in the policy, Global.Sentinel):
      normal < watch < restricted < quarantine
      - watch: alert in the log (ALERT level, hence SIEM) and a warning appended to the agent's responses;
      - restricted: no direct access to the vCenters, only diagnostics and the cached inventory remain allowed;
      - quarantine: agent automatically suspended (revocation), notification, MIThrandir switches to PROTECTION MODE.
    Global protection mode: if several agents are quarantined within a short window, all agents
    are restricted until an administrator acknowledges.
    Notifications: ALERT log (exported to Splunk / SIEM), console banner, webhook (Teams, Mattermost,
    generic JSON) and SMTP email, configured in MIThrandir.config.psd1 (Alerts section).
    Persistent state: journal\sentinel.json (quarantines survive a restart).
#>

$Script:Sentinel = @{ agents = @{}; protection = @{ active = $false; globalSettings = $false; since = ''; reason = '' }; inProgress = $false }
$Script:SentinelCategories = [ordered]@{
    bypass = 'Bypass attempt (variables, .NET types, invocation, redirection, commands outside PowerCLI)'
    write      = 'Write action attempt (Set-, Remove-, Stop-, New-, Invoke- ...)'
    sensitive      = 'Access to sensitive data (excluded cmdlet, masked parameter or property)'
    poll       = 'Probing (unknown tools or methods, many different denied cmdlets)'
    scope     = 'Outside scope (vCenter not allowed or unknown)'
    rule         = 'Denial by a rule (command not covered or forbidden)'
    quota         = 'Quota exceeded'
    burst        = 'Abnormal call rate'
    syntax       = 'Syntax error or unknown parameter (often in good faith)'
    restricted     = 'Call denied because the agent is already restricted or suspended'
}

function Get-SentinelConfig {
    $default = @{
        Active = $true; HalfLifeMinutes = 30
        WatchThreshold = 25; RestrictionThreshold = 50; QuarantineThreshold = 80
        AutomaticQuarantine = $true; AgentsGlobalProtection = 2; ProtectionWindowMinutes = 30
        MaxCallsPerMinute = 60
        Weight = @{ bypass = 15; write = 12; sensitive = 10; poll = 8; scope = 6; rule = 4; quota = 3; burst = 10; syntax = 1; restricted = 5 }
    }
    $g = if ($Script:Policy -and $Script:Policy.Global.ContainsKey('Sentinel')) { $Script:Policy.Global.Sentinel } else { @{} }
    foreach ($key in @($g.Keys)) {
        if ($key -eq 'Weight' -and $g.Weight -is [hashtable]) { foreach ($k in @($g.Weight.Keys)) { $default.Weight[$k] = [double]$g.Weight[$k] } }
        else { $default[$key] = $g[$key] }
    }
    return $default
}

function Test-SentinelConfig {
    <# Called by Test-PolicyConsistency: normalizes Global.Sentinel or throws an exception. #>
    param([hashtable]$Value)
    if ($null -eq $Value) { return $null }
    $v = $Value
    foreach ($key in @('HalfLifeMinutes', 'WatchThreshold', 'RestrictionThreshold', 'QuarantineThreshold', 'AgentsGlobalProtection', 'ProtectionWindowMinutes', 'MaxCallsPerMinute')) {
        if ($v.ContainsKey($key)) { try { $v[$key] = [int]$v[$key] } catch { throw "Global.Sentinel.$key must be a number" } }
    }
    foreach ($key in @('Active', 'AutomaticQuarantine')) { if ($v.ContainsKey($key)) { $v[$key] = [bool]$v[$key] } }
    $s = if ($v.ContainsKey('WatchThreshold')) { $v.WatchThreshold } else { 25 }
    $r = if ($v.ContainsKey('RestrictionThreshold')) { $v.RestrictionThreshold } else { 50 }
    $q = if ($v.ContainsKey('QuarantineThreshold')) { $v.QuarantineThreshold } else { 80 }
    if (-not ($s -gt 0 -and $s -lt $r -and $r -lt $q -and $q -le 100)) { throw 'Global.Sentinel: 0 < watch < restriction < quarantine <= 100 is required' }
    if ($v.ContainsKey('HalfLifeMinutes') -and ($v.HalfLifeMinutes -lt 1 -or $v.HalfLifeMinutes -gt 1440)) { throw 'Global.Sentinel.HalfLifeMinutes: from 1 to 1440' }
    if ($v.ContainsKey('Weight')) {
        if ($v.Weight -isnot [hashtable]) { throw 'Global.Sentinel.Weight: invalid format' }
        foreach ($k in @($v.Weight.Keys)) {
            if (-not $Script:SentinelCategories.Contains($k)) { throw "Global.Sentinel.Weight: unknown category: $k" }
            try { $v.Weight[$k] = [double]$v.Weight[$k] } catch { throw "Global.Sentinel.Weight.$k must be a number" }
            if ($v.Weight[$k] -lt 0 -or $v.Weight[$k] -gt 100) { throw "Global.Sentinel.Weight.$k must be from 0 to 100" }
        }
    }
    return $v
}

function Get-DenialCategory {
    <# Nature of a refusal, derived from the reason given by the policy or by syntax analysis. #>
    param([string]$Text)
    $t = $Text
    if ($t -match 'suspended|restricted by the Sentinel|quarantine|gateway suspended') { return 'restricted' }
    if ($t -match "invalid identity signature|is not a trusted relay|unreadable identity assertion") { return 'bypass' }
    if ($t -match 'construct denied|nested expression|variable denied|static access|dynamic member|script block|invocation operator|non-constant command name|command path|a single statement|redirection|command outside PowerCLI|after rewriting') { return 'bypass' }
    if ($t -match 'cmdlet not allowed: (Set|Remove|New|Stop|Start|Restart|Suspend|Move|Invoke|Update|Add|Install|Uninstall|Copy|Connect|Disconnect|Export|Import|Mount|Dismount|Enable|Disable|Reset|Register|Unregister|Wait|Open|Apply|Format)-') { return 'write' }
    if ($t -match 'cmdlet excluded|parameter -\S+ denied|property excluded|not allowed by the allow list') { return 'sensitive' }
    if ($t -match 'Unknown tool|Unsupported method|cmdlet not allowed') { return 'poll' }
    if ($t -match 'outside the scope|unknown vCenter|no vCenter in the scope') { return 'scope' }
    if ($t -match 'quota') { return 'quota' }
    if ($t -match 'denied by rule|no rule allows') { return 'rule' }
    if ($t -match 'invalid syntax|unknown on|ambiguous|unknown command') { return 'syntax' }
    return 'rule'
}

function Get-SentinelAgentState {
    param([string]$IP)
    if (-not $Script:Sentinel.agents.ContainsKey($IP)) {
        $Script:Sentinel.agents[$IP] = @{
            ip = $IP; score = 0.0; confidence = 50.0; level = 'normal'; upd = (Get-Date)
            signals = [System.Collections.Generic.List[object]]::new()
            calls = [System.Collections.Generic.List[datetime]]::new(); denial = [System.Collections.Generic.List[object]]::new()
            lastBurst = [datetime]::MinValue; quarantine = $null; passed = 0; denialsTotal = 0
        }
    }
    $a = $Script:Sentinel.agents[$IP]
    # Exponential decay of the score since the last computation
    $cfg = Get-SentinelConfig
    $minutes = ((Get-Date) - $a.upd).TotalMinutes
    if ($minutes -gt 0) { $a.score = $a.score * [math]::Pow(0.5, $minutes / [math]::Max(1, $cfg.HalfLifeMinutes)); $a.upd = Get-Date }
    return $a
}

function Get-SentinelLevel {
    param([double]$Score, [hashtable]$Agent)
    $cfg = Get-SentinelConfig
    if ($Agent -and $Agent.quarantine) { return 'quarantine' }
    if ($Score -ge $cfg.QuarantineThreshold) { return 'quarantine' }
    if ($Score -ge $cfg.RestrictionThreshold) { return 'restricted' }
    if ($Score -ge $cfg.WatchThreshold) { return 'watch' }
    return 'normal'
}

function Register-SentinelSignal {
    <# Called by Write-Journal for every CALL and DENIED of an agent. #>
    param([System.Collections.IDictionary]$LogEvent)
    if ($Script:Sentinel.inProgress) { return }
    $cfg = Get-SentinelConfig
    if (-not $cfg.Active) { return }
    # Tracking key: the person when identified, otherwise the agent's IP address
    $ip = if ($LogEvent.Contains('user') -and $LogEvent.user) { [string]$LogEvent.user } else { [string]$LogEvent.agent }
    if (-not $ip) { return }
    $message = [string]$LogEvent.message
    if ($message -like 'Console*') { return }
    $Script:Sentinel.inProgress = $true
    try {
        $a = Get-SentinelAgentState -IP $ip
        $now = Get-Date
        if ($LogEvent.level -eq 'CALL') {
            if ($message -notlike 'Execution of *') { return }
            $a.passed++
            $a.calls.Add($now)
            $a.calls.RemoveAll({ param($h) $h -lt $now.AddMinutes(-1) }) | Out-Null
            $a.confidence = [math]::Min(100, $a.confidence + 0.5)
            $a.score = [math]::Max(0, $a.score - 0.5)
            if ($a.calls.Count -gt $cfg.MaxCallsPerMinute -and ($now - $a.lastBurst).TotalSeconds -ge 60) {
                $a.lastBurst = $now
                Add-SentinelWeights -Agent $a -Category 'burst' -Weight $cfg.Weight.burst -Detail "$($a.calls.Count) calls in one minute (maximum $($cfg.MaxCallsPerMinute))"
            }
        }
        elseif ($LogEvent.level -eq 'DENIED') {
            if ($a.quarantine) { $a.denialsTotal++; return }   # already revoked: count it without cluttering the history
            $reason = if ($LogEvent.data -and $LogEvent.data.Contains('reason')) { [string]$LogEvent.data['reason'] } else { $message }
            if ($reason -eq '') { $reason = $message }
            $category = Get-DenialCategory -Text "$message $reason"
            $a.denialsTotal++
            $a.denial.Add(@{ h = $now; c = $category; d = $reason })
            $a.denial.RemoveAll({ param($r) $r.h -lt $now.AddMinutes(-10) }) | Out-Null
            # Repetition: several refusals within 10 minutes amplify the weight; probing: many different causes
            $num = $a.denial.Count
            $multiplier = if ($num -ge 8) { 2.0 } elseif ($num -ge 4) { 1.5 } else { 1.0 }
            $weight = [double]$cfg.Weight[$category] * $multiplier
            $a.confidence = [math]::Max(0, $a.confidence - [math]::Min(10, $weight / 2))
            $detail = $reason
            if ($multiplier -gt 1) { $detail = "$reason (repeated: $num denials in 10 min, weight x$multiplier)" }
            Add-SentinelWeights -Agent $a -Category $category -Weight $weight -Detail $detail
            $different = @($a.denial | ForEach-Object { $_.d } | Select-Object -Unique).Count
            if ($different -ge 6 -and $category -ne 'restricted' -and -not ($a.signals | Where-Object { $_.category -eq 'poll' -and $_.timestamp -gt $now.AddMinutes(-10).ToString('o') })) {
                Add-SentinelWeights -Agent $a -Category 'poll' -Weight $cfg.Weight.poll -Detail "$different distinct denial reasons in 10 minutes"
            }
        }
        Update-SentinelLevel -Agent $a
    }
    finally { $Script:Sentinel.inProgress = $false }
}

function Add-SentinelWeights {
    param([hashtable]$Agent, [string]$Category, [double]$Weight, [string]$Detail)
    if ($Weight -le 0) { return }
    $Agent.score = [math]::Min(100, $Agent.score + $Weight)
    $Agent.signals.Add([ordered]@{ timestamp = (Get-Date).ToString('o'); category = $Category; weight = [math]::Round($Weight, 1); score = [math]::Round($Agent.score, 1); detail = $Detail })
    if ($Agent.signals.Count -gt 100) { $Agent.signals.RemoveRange(0, $Agent.signals.Count - 100) }
}

function Update-SentinelLevel {
    param([hashtable]$Agent)
    $cfg = Get-SentinelConfig
    $before = $Agent.level
    $after = Get-SentinelLevel -Score $Agent.score -Agent $Agent
    if ($after -eq 'quarantine' -and -not $Agent.quarantine) {
        if (-not $cfg.AutomaticQuarantine) { $after = 'restricted' }
        else { Set-AgentQuarantine -IP $Agent.ip -Reason "suspicion score $([math]::Round($Agent.score)) (threshold $($cfg.QuarantineThreshold))" -By 'Sentinel' -Agent $Agent }
    }
    $Agent.level = $after
    if ($after -ne $before) {
        $order = @{ normal = 0; watch = 1; restricted = 2; quarantine = 3 }
        $rise = $order[$after] -gt $order[$before]
        $latest = @($Agent.signals | Select-Object -Last 3 | ForEach-Object { "$($_.category): $($_.detail)" })
        $data = @{ ip = $Agent.ip; agent = $Agent.ip; before = $before; after = $after; score = [math]::Round($Agent.score, 1); confidence = [math]::Round($Agent.confidence); latestSignals = $latest }
        if ($rise) {
            Write-Journal -Level 'ALERT' -Message "Sentinel: agent $($Agent.ip) moved from $before to $after" -Data $data
            if ($after -in @('restricted', 'quarantine')) { Send-AlertMIThrandir -Title "MIThrandir: agent $($Agent.ip) $after" -Text ("Agent $($Agent.ip) moved to level '$after' (suspicion score $([math]::Round($Agent.score)) out of 100).`nLatest signals:`n- " + ($latest -join "`n- ")) -Severity $after }
        }
        else { Write-Journal -Level 'INFO' -Message "Sentinel: agent $($Agent.ip) dropped from $before to $after" -Data $data }
    }
}

function Set-AgentQuarantine {
    <# Revocation: the agent is suspended (same mechanism as manual suspension) and MIThrandir switches to protection mode. #>
    param([string]$IP, [string]$Reason, [string]$By, [hashtable]$Agent)
    if (-not $Agent) { $Agent = Get-SentinelAgentState -IP $IP }
    $cfg = Get-SentinelConfig
    $Agent.quarantine = [ordered]@{ since = (Get-Date).ToString('o'); by = $By; reason = $Reason; score = [math]::Round($Agent.score, 1) }
    $Agent.level = 'quarantine'
    $Script:SuspendedAgents[$IP] = [ordered]@{ by = $By; since = (Get-Date).ToString('o'); reason = "quarantine: $Reason"; sentinel = $true }
    if (-not $Script:Sentinel.protection.active) { $Script:Sentinel.protection.since = (Get-Date).ToString('o') }
    $Script:Sentinel.protection.active = $true
    $Script:Sentinel.protection.reason = "agent $IP in quarantine ($Reason)"
    # Escalation: several quarantines in quick succession => all agents restricted
    $threshold = (Get-Date).AddMinutes(-$cfg.ProtectionWindowMinutes).ToString('o')
    $recent = @($Script:Sentinel.agents.Values | Where-Object { $_.quarantine -and $_.quarantine.since -gt $threshold })
    if ($recent.Count -ge $cfg.AgentsGlobalProtection -and -not $Script:Sentinel.protection.globalSettings) {
        $Script:Sentinel.protection.globalSettings = $true
        $Script:Sentinel.protection.reason = "$($recent.Count) agents in quarantine within $($cfg.ProtectionWindowMinutes) min: all agents are restricted"
        Write-Journal -Level 'ALERT' -Message 'Sentinel: GLOBAL PROTECTION MODE, all agents are restricted' -Data @{ agents = @($recent.ip) }
        Send-AlertMIThrandir -Title 'MIThrandir: GLOBAL PROTECTION MODE' -Text "$($recent.Count) agents placed in quarantine within $($cfg.ProtectionWindowMinutes) minutes ($(@($recent.ip) -join ', ')). All agents are restricted to diagnostics and the cached inventory until acknowledged in the console." -Severity 'globalSettings'
    }
    Write-Journal -Level 'ALERT' -Message "Sentinel: agent $IP placed in quarantine, access revoked" -Data @{ ip = $IP; agent = $IP; by = $By; reason = $Reason; score = [math]::Round($Agent.score, 1) }
    Save-SentinelState
}

function Clear-AgentQuarantine {
    <# Acknowledgement by an administrator: quarantine lifted, score reset to zero, medium confidence. #>
    param([string]$IP, [string]$Author)
    $a = Get-SentinelAgentState -IP $IP
    $a.quarantine = $null; $a.score = 0.0; $a.level = 'normal'; $a.confidence = [math]::Max($a.confidence, 40); $a.denial.Clear()
    if ($Script:SuspendedAgents.ContainsKey($IP) -and $Script:SuspendedAgents[$IP].Contains('sentinel')) { $Script:SuspendedAgents.Remove($IP) }
    if (-not @($Script:Sentinel.agents.Values | Where-Object { $_.quarantine })) {
        $Script:Sentinel.protection = @{ active = $false; globalSettings = $false; since = ''; reason = '' }
    }
    Write-Journal -Level 'ADMIN' -Message "Sentinel: agent $IP acknowledged, quarantine lifted" -Data @{ author = $Author; agent = $IP }
    Save-SentinelState
}

function Clear-GlobalProtection {
    param([string]$Author)
    $Script:Sentinel.protection.globalSettings = $false
    if (-not @($Script:Sentinel.agents.Values | Where-Object { $_.quarantine })) { $Script:Sentinel.protection = @{ active = $false; globalSettings = $false; since = ''; reason = '' } }
    Write-Journal -Level 'ADMIN' -Message 'Sentinel: global protection lifted' -Data @{ author = $Author }
    Save-SentinelState
}

function Test-SentinelAccess {
    <# Before any execution (Test-Policy): refuse if the agent is restricted or global protection is active. #>
    param([string]$IP, [string]$ToolName)
    $cfg = Get-SentinelConfig
    if (-not $cfg.Active) { return @{ Allowed = $true } }
    $allowed = @('Get-MIThrandirTime', 'Get-VIServer', 'Get-MIThrandirInventory')
    $level = if ($Script:Sentinel.agents.ContainsKey($IP)) { (Get-SentinelAgentState -IP $IP).level } else { 'normal' }
    if ($level -eq 'restricted' -and $ToolName -notin $allowed) { return @{ Allowed = $false; Reason = "agent restricted by the Sentinel of MIThrandir (suspicious behavior): only diagnostics and the cached inventory remain allowed" } }
    if ($Script:Sentinel.protection.globalSettings -and $ToolName -notin $allowed) { return @{ Allowed = $false; Reason = "MIThrandir is in global protection mode: only diagnostics and the cached inventory remain allowed" } }
    return @{ Allowed = $true }
}

function Get-SentinelWarning {
    <# Text appended to the responses of an agent under watch: the model is warned, which is often enough to correct an unintentional drift. #>
    param([string]$IP)
    if (-not $Script:Sentinel.agents.ContainsKey($IP)) { return '' }
    $a = $Script:Sentinel.agents[$IP]
    switch ($a.level) {
        'watch' { return "`n[MIThrandir] Warning: several denied requests were detected for this agent. Stick to the allowed tools and cmdlets; bypass attempts lead to restriction, then automatic quarantine." }
        'restricted'    { return "`n[MIThrandir] Access restricted: suspicious behavior detected. Only diagnostics and the cached inventory remain available; an administrator has been notified." }
        default        { return '' }
    }
}

function Get-SentinelView {
    $cfg = Get-SentinelConfig
    $list = @(foreach ($ip in @($Script:Sentinel.agents.Keys)) {
        $a = Get-SentinelAgentState -IP $ip
        $newItem = Get-SentinelLevel -Score $a.score -Agent $a
        if ($newItem -ne $a.level -and -not $a.quarantine) { Update-SentinelLevel -Agent $a }
        [ordered]@{
            ip = $ip; score = [math]::Round($a.score, 1); confidence = [math]::Round($a.confidence); level = $a.level
            passed = $a.passed; denialsTotal = $a.denialsTotal; denials10min = $a.denial.Count; callsMinute = $a.calls.Count
            quarantine = $a.quarantine; signals = @($a.signals | Select-Object -Last 30)
        }
    })
    return [ordered]@{ config = $cfg; categories = $Script:SentinelCategories; protection = $Script:Sentinel.protection; agents = @($list | Sort-Object { $_.score } -Descending) }
}

function Save-SentinelState {
    try {
        $state = @{ protection = $Script:Sentinel.protection; quarantines = @(foreach ($a in $Script:Sentinel.agents.Values) { if ($a.quarantine) { @{ ip = $a.ip; quarantine = $a.quarantine; score = $a.score; signals = @($a.signals | Select-Object -Last 20) } } }) }
        [System.IO.File]::WriteAllText((Join-Path $Script:JournalPath 'sentinel.json'), ($state | ConvertTo-Json -Depth 6), [System.Text.UTF8Encoding]::new($false))
    }
    catch { }
}

function Initialize-Sentinel {
    $file = Join-Path $Script:JournalPath 'sentinel.json'
    if (-not (Test-Path $file)) { return }
    try {
        $state = [System.IO.File]::ReadAllText($file) | ConvertFrom-Json -AsHashtable -Depth 8
        foreach ($q in @($state.quarantines)) {
            if (-not $q) { continue }
            $a = Get-SentinelAgentState -IP $q.ip
            $a.quarantine = $q.quarantine; $a.score = [double]$q.score; $a.level = 'quarantine'
            foreach ($s in @($q.signals)) { if ($s) { $a.signals.Add($s) } }
            $Script:SuspendedAgents[$q.ip] = [ordered]@{ by = 'Sentinel'; since = [string]$q.quarantine.since; reason = "quarantine: $($q.quarantine.reason)"; sentinel = $true }
        }
        if ($state.protection) { $Script:Sentinel.protection = @{ active = [bool]$state.protection.active; globalSettings = [bool]$state.protection.globalSettings; since = [string]$state.protection.since; reason = [string]$state.protection.reason } }
        if ($Script:Sentinel.protection.active) { Write-Journal -Level 'ALERT' -Message 'Sentinel: MIThrandir restarted in PROTECTION MODE (quarantines kept)' -Data @{ reason = $Script:Sentinel.protection.reason } }
    }
    catch { Write-Journal -Level 'ERROR' -Message "Sentinel state unreadable: $file" -Data @{ error = $_.Exception.Message } }
}

# ---------------------------------------------------------------------------
# Notifications outside MIThrandir: webhook (Teams, Mattermost, JSON) and email. Asynchronous, never blocking.
# MIThrandir.config.psd1 :
#   Alerts = @{
#       Webhook = @{ Active = $false; Url = 'https://...'; Format = 'teams' }   # 'teams', 'mattermost' (or Slack) or 'json'
#       Smtp    = @{ Active = $false; Server = 'smtp.example.local'; Port = 25; Ssl = $false; From = 'mithrandir@example.local'; To = @('team@example.local') }
#   }
# ---------------------------------------------------------------------------
$Script:AlertsHttpClient = $null

function Send-AlertMIThrandir {
    param([string]$Title, [string]$Text, [string]$Severity = 'restricted')
    $alerts = if ($Script:Config.ContainsKey('Alerts')) { $Script:Config.Alerts } else { @{} }
    $machine = $env:COMPUTERNAME
    $textBody = "$Text`n`nGateway: $machine, $(Get-Date -Format 'dd.MM.yyyy HH:mm:ss'). Console: $($Script:ConsoleAlertPrefix)"
    if ($alerts.ContainsKey('Webhook') -and $alerts.Webhook.Active -and $alerts.Webhook.Url) {
        try {
            if (-not $Script:AlertsHttpClient) { $Script:AlertsHttpClient = [System.Net.Http.HttpClient]::new(); $Script:AlertsHttpClient.Timeout = [TimeSpan]::FromSeconds(10) }
            $format = if ($alerts.Webhook.Format) { [string]$alerts.Webhook.Format } else { 'json' }
            $charge = switch ($format) {
                'teams'      { @{ '@type' = 'MessageCard'; '@context' = 'https://schema.org/extensions'; themeColor = $(if ($Severity -eq 'restricted') { 'E8A13A' } else { 'F0625A' }); title = $Title; text = ($textBody -replace "`n", '<br>') } }
                'mattermost' { @{ text = "**$Title**`n$textBody" } }
                default      { @{ title = $Title; text = $textBody; severity = $Severity; machine = $machine; timestamp = (Get-Date).ToString('o'); source = 'mithrandir' } }
            }
            $content = [System.Net.Http.StringContent]::new(($charge | ConvertTo-Json -Depth 4 -Compress), [System.Text.Encoding]::UTF8, 'application/json')
            [void]$Script:AlertsHttpClient.PostAsync([string]$alerts.Webhook.Url, $content)
        }
        catch { Write-Host "Alert webhook not sent: $($_.Exception.Message)" -ForegroundColor DarkYellow }
    }
    if ($alerts.ContainsKey('Smtp') -and $alerts.Smtp.Active -and $alerts.Smtp.Server -and $alerts.Smtp.To) {
        try {
            $client = [System.Net.Mail.SmtpClient]::new([string]$alerts.Smtp.Server, $(if ($alerts.Smtp.Port) { [int]$alerts.Smtp.Port } else { 25 }))
            $client.EnableSsl = [bool]$alerts.Smtp.Ssl
            $client.UseDefaultCredentials = $true
            $email = [System.Net.Mail.MailMessage]::new()
            $email.From = [string]$alerts.Smtp.From
            foreach ($d in @($alerts.Smtp.To)) { $email.To.Add([string]$d) }
            $email.Subject = $Title; $email.Body = $textBody; $email.Priority = [System.Net.Mail.MailPriority]::High
            [void]$client.SendMailAsync($email)
        }
        catch { Write-Host "Alert email not sent: $($_.Exception.Message)" -ForegroundColor DarkYellow }
    }
}
