#Requires -Version 7.0
<#
.SYNOPSIS
    MIThrandir V4.6 tests: property bypasses closed, bounded Get-View, mandatory targeting, Origin header.
    Run against a running MIThrandir instance (mock-up), with a policy where Get-View is allowed
    (read-views group in an Allow (allow) rule, and Get-View removed from ExcludedCmdlets in the global
    settings), and a rule allowing Get-Stat (read-performance group). The default policy allows neither:
    the three legitimate-read tests that need them are then reported as [PREREQ] and not counted.

    These tests send many refused lines: the Sentinel would restrict then quarantine the test client and
    distort the results (such lines are reported as [SENTINEL], not as passed). Disable it for the run
    (console: Global settings, Sentinel) or use a dedicated test instance.

.EXAMPLE
    .\_tests_v46.ps1
    .\_tests_v46.ps1 -Url http://MITHRANDIR-01:8765/mcp -Token MyToken -VCenter vc-prod-1
#>
[CmdletBinding()]
param(
    [string]$Url = 'http://localhost:8765/mcp',
    [string]$Token = '',
    [string]$VCenter = '',
    [string]$ExistingVmName = ''   # a real VM for legitimate reads; otherwise limit to the denial tests
)

$ErrorActionPreference = 'Stop'
$headers = @{ 'Content-Type' = 'application/json'; 'Accept' = 'application/json, text/event-stream' }
if ($Token) { $headers['Authorization'] = "Bearer $Token" }
$script:counter = 0

function Send-Mcp {
    param([string]$Method, [hashtable]$Params = @{}, [switch]$Notification, [hashtable]$ExtraHeaders = @{})
    $script:counter++
    $message = @{ jsonrpc = '2.0'; method = $Method; params = $Params }
    if (-not $Notification) { $message.id = $script:counter }
    $e = @{}; foreach ($k in $headers.Keys) { $e[$k] = $headers[$k] }; foreach ($k in $ExtraHeaders.Keys) { $e[$k] = $ExtraHeaders[$k] }
    $response = Invoke-WebRequest -Uri $Url -Method Post -Headers $e -Body ($message | ConvertTo-Json -Depth 12 -Compress) -SkipHttpErrorCheck
    $idSession = $response.Headers['Mcp-Session-Id']; if ($idSession) { $headers['Mcp-Session-Id'] = [string]$idSession }
    return @{ Http = [int]$response.StatusCode; Object = $(if ($response.Content) { $response.Content | ConvertFrom-Json -Depth 30 } else { $null }) }
}

# MCP handshake
Send-Mcp -Method 'initialize' -Params @{ protocolVersion = '2025-06-18'; capabilities = @{}; clientInfo = @{ name = 'Test-V46'; version = '1.0' } } | Out-Null
Send-Mcp -Method 'notifications/initialized' -Notification | Out-Null

$script:passed = 0; $script:total = 0; $script:prerequisite = 0
function Invoke-Line {
    param([string]$Line, [int]$Limit = 25)
    $args = @{ Line = $Line }; if ($Limit) { $args.Limit = $Limit }
    $r = Send-Mcp -Method 'tools/call' -Params @{ name = 'Invoke-PowerCLI'; arguments = $args }
    $text = ''; $isError = $false
    if ($r.Object.result) { $isError = [bool]$r.Object.result.isError; $text = ($r.Object.result.content | ForEach-Object { $_.text }) -join "`n" }
    elseif ($r.Object.error) { $isError = $true; $text = $r.Object.error.message }
    # a validation refusal comes back as text "Error while executing ... Line denied by MIThrandir"
    $isDenied = $isError -or $text -match 'denied by MIThrandir|Line denied|Action denied'
    return @{ Denied = $isDenied; Text = $text; Sentinel = [bool]($text -match 'sentinel') }
}
function Test-Line {
    param([string]$Name, [string]$Line, [ValidateSet('OK', 'DENIED')][string]$Expected, [string[]]$Forbidden = @(), [string[]]$Present = @())
    $script:total++
    $r = Invoke-Line -Line $Line
    if ($r.Sentinel) {
        Write-Host ('[SENTINEL] {0,-34} blocked by the Sentinel: test inconclusive (disable Global.Sentinel.Active to replay)' -f $Name) -ForegroundColor Yellow
        return
    }
    if ($Expected -eq 'OK' -and $r.Denied -and $r.Text -match 'excluded by the policy|no rule allows') {
        $script:total--; $script:prerequisite++
        Write-Host ('[PREREQ]   {0,-34} denied by the current policy: allow this read in the policy to validate this test' -f $Name) -ForegroundColor Yellow
        return
    }
    $obtained = if ($r.Denied) { 'DENIED' } else { 'OK' }
    $leak = @($Forbidden | Where-Object { $r.Text -match [regex]::Escape($_) })
    $missing = @($Present | Where-Object { $r.Text -notmatch [regex]::Escape($_) })
    $ok = ($obtained -eq $Expected) -and $leak.Count -eq 0 -and $missing.Count -eq 0
    if ($ok) { $script:passed++ }
    $color = if ($ok) { 'Green' } else { 'Red' }
    Write-Host ("[{0}] {1,-38} expected={2,-5} observed={3,-5} {4}{5}" -f $(if ($ok) { 'passed' } else { 'FAILED' }), $Name, $Expected, $obtained, $(if ($leak.Count) { "LEAK:$($leak -join ',') " } else { '' }), $(if ($missing.Count) { "MISSING:$($missing -join ',')" } else { '' })) -ForegroundColor $color
}

$srv = if ($VCenter) { " -Server $VCenter" } else { '' }
$vm = if ($ExistingVmName) { $ExistingVmName } else { '' }

Write-Host "`n=== Property bypasses (must be DENIED) ===" -ForegroundColor Cyan
if ($vm) {
    Test-Line 'ExpandProperty N*tes'        "Get-VM -Name $vm$srv | Select-Object -ExpandProperty N*tes" DENIED
    Test-Line 'calc E=Notes'                "Get-VM -Name $vm$srv | Select-Object Name, @{N='n';E='Notes'}" DENIED
    Test-Line 'ExtensionData by wildcard' "Get-VM -Name $vm$srv | Select-Object -ExpandProperty Ext*" DENIED
    Test-Line 'access PSObject'              "Get-VM -Name $vm$srv | Where-Object { `$_.PSObject.Properties['Notes'].Value }" DENIED
    Test-Line 'Get-Annotation'              "Get-VM -Name $vm$srv | Get-Annotation" DENIED
    Test-Line 'Get-AdvancedSetting guest'   "Get-VM -Name $vm$srv | Get-AdvancedSetting -Name 'guestinfo.*'" DENIED
}
Test-Line 'oracle Where N*tes'          "Get-VM$srv | Where-Object -Property N*tes -Like 'pwd*' | Measure-Object" DENIED

Write-Host "`n=== Bounded Get-View (must be DENIED) ===" -ForegroundColor Cyan
Test-Line 'Get-View without Property' "Get-View -ViewType VirtualMachine$srv" DENIED
Test-Line 'Get-View ancestor Config' "Get-View -ViewType VirtualMachine -Property Config$srv" DENIED
Test-Line 'Get-View Annotation'         "Get-View -ViewType VirtualMachine -Property Name, Config.Annotation$srv" DENIED
Test-Line 'Get-View ExtraConfig'        "Get-View -ViewType VirtualMachine -Property Config.ExtraConfig$srv" DENIED
Test-Line 'Get-View SessionManager'     "Get-View -ViewType SessionManager -Property CurrentSession$srv" DENIED
Test-Line 'Get-View -Id SessionManager' "Get-View -Id 'SessionManager' -Property CurrentSession$srv" DENIED

Write-Host "`n=== Mandatory targeting (must be DENIED) ===" -ForegroundColor Cyan
Test-Line 'Get-Stat global'             "Get-Stat -Stat cpu.usage.average$srv | Measure-Object" DENIED
Test-Line 'Get-TagAssignment global'    "Get-TagAssignment$srv | Measure-Object" DENIED

Write-Host "`n=== Legitimate reads (must PASS) ===" -ForegroundColor Cyan
Test-Line 'Get-VM simple'               "Get-VM$srv | Select-Object Name, PowerState" OK
Test-Line 'Where -Like on value' "Get-VM$srv | Where-Object Name -Like '*' | Measure-Object" OK
Test-Line 'Get-View bounded Property' "Get-View -ViewType VirtualMachine -Property Name, Config.Tools.ToolsVersion$srv" OK -Forbidden @('Annotation', 'ExtraConfig')
if ($vm) {
    Test-Line 'Get-View pipe target'     "Get-VM -Name $vm$srv | Get-View -Property Name, Runtime.PowerState" OK
    Test-Line 'Get-Stat target by pipe' "Get-VM -Name $vm$srv | Get-Stat -Stat cpu.usage.average -MaxSamples 1 -Realtime" OK
}

Write-Host "`n=== Origin header (anti-CSRF) ===" -ForegroundColor Cyan
$script:total++
$rOrig = Send-Mcp -Method 'tools/call' -Params @{ name = 'Get-MIThrandirTime'; arguments = @{} } -ExtraHeaders @{ 'Origin' = 'http://site-pirate.example' }
if ($rOrig.Http -eq 403) { $script:passed++; Write-Host "[passed] Hostile origin denied (HTTP 403)" -ForegroundColor Green }
else { Write-Host "[FAILED] Hostile origin: HTTP $($rOrig.Http) (expected 403 if AllowedOrigins does not cover it)" -ForegroundColor Red }

if ($script:prerequisite) { Write-Host "$script:prerequisite test(s) not evaluated: policy prerequisites missing." -ForegroundColor Yellow }
Write-Host "`n$script:passed / $script:total passed" -ForegroundColor $(if ($script:passed -eq $script:total) { 'Green' } else { 'Yellow' })
