#Requires -Version 7.0
<#
.SYNOPSIS
    Demo: sends allowed and forbidden PowerCLI lines to a running MIThrandir and shows what happens.

.DESCRIPTION
    Each line is sent as an agent would send it (MCP tools/call on Invoke-PowerCLI). The expected outcome is
    shown next to the observed one, with the refusal reason. Run it against an instance connected to a vCenter
    simulator (see demo/README.md) with the default policy. With a custom policy, some outcomes will differ.

    The Sentinel watches every agent. After a few refusals in a short time it restricts, then quarantines,
    the agent (here: your IP address). That is the product working, but it hides which wall refused a line, so by
    default the script sends only a few refused lines. With -Full it sends more, and lines blocked by the
    Sentinel are reported as such. Release the agent from the Sentinel page of the console to start over (the state survives restarts).

.EXAMPLE
    .\demo\Demo-Lines.ps1
    .\demo\Demo-Lines.ps1 -Full
    .\demo\Demo-Lines.ps1 -Url http://localhost:8765/mcp -Token MyToken
#>
[CmdletBinding()]
param(
    [string]$Url = 'http://localhost:8765/mcp',
    [string]$Token = '',
    [switch]$Full
)

$ErrorActionPreference = 'Stop'
$headers = @{ 'Content-Type' = 'application/json'; 'Accept' = 'application/json, text/event-stream' }
if ($Token) { $headers['Authorization'] = "Bearer $Token" }
$script:counter = 0

function Send-Mcp {
    param([string]$Method, [hashtable]$Params = @{}, [switch]$Notification)
    $script:counter++
    $message = @{ jsonrpc = '2.0'; method = $Method; params = $Params }
    if (-not $Notification) { $message.id = $script:counter }
    $response = Invoke-WebRequest -Uri $Url -Method Post -Headers $headers -Body ($message | ConvertTo-Json -Depth 12 -Compress) -SkipHttpErrorCheck
    $idSession = $response.Headers['Mcp-Session-Id']
    if ($idSession) { $headers['Mcp-Session-Id'] = [string]$idSession }
    if ($response.Content) { return ($response.Content | ConvertFrom-Json -Depth 30) }
}

[void](Send-Mcp -Method 'initialize' -Params @{ protocolVersion = '2025-06-18'; capabilities = @{}; clientInfo = @{ name = 'Demo-Lines'; version = '1.0' } })
[void](Send-Mcp -Method 'notifications/initialized' -Notification)

# Expected: 'Allowed' (the line runs) or 'Denied' (blocked before execution)
$lines = @(
    @{ Expected = 'Allowed'; Line = 'Get-VM | Select-Object -First 5 Name, PowerState' }
    @{ Expected = 'Allowed'; Line = 'Get-VM | Measure-Object' }
    @{ Expected = 'Allowed'; Line = 'Get-Cluster | Select-Object Name' }
    @{ Expected = 'Allowed'; Line = 'Get-VMHost | Sort-Object Name | Select-Object -First 3 Name, ConnectionState' }
    @{ Expected = 'Denied';   Line = 'Get-VM | Stop-VM -Confirm:$false' }
    @{ Expected = 'Denied';   Line = 'Get-VM | ForEach-Object { $_.PowerOffVM_Task() }' }
    @{ Expected = 'Denied';   Line = 'Get-VM | Select-Object -ExpandProperty N*tes' }
    @{ Expected = 'Denied';   Line = 'Get-VM | Get-AdvancedSetting -Name "guestinfo.*"' }
)
if ($Full) {
    $lines += @(
        @{ Expected = 'Denied'; Line = 'Get-VM | Remove-VM -DeletePermanently' }
        @{ Expected = 'Denied'; Line = 'Invoke-Expression "Get-VM"' }
        @{ Expected = 'Denied'; Line = 'Get-VM | Select-Object Name, @{N="x";E="Notes"}' }
        @{ Expected = 'Denied'; Line = 'Get-View -ViewType VirtualMachine -Property Config.ExtraConfig' }
        @{ Expected = 'Denied'; Line = 'Connect-VIServer -Server evil.example.com' }
    )
}

$compliant = 0; $bySentinel = 0
foreach ($element in $lines) {
    $response = Send-Mcp -Method 'tools/call' -Params @{ name = 'Invoke-PowerCLI'; arguments = @{ Line = $element.Line } }
    $toolError = [bool]($response.error -or $response.result.isError)
    $text = ''
    if ($toolError) {
        $text = if ($response.result.content) { ($response.result.content | ForEach-Object { $_.text }) -join ' ' } else { [string]$response.error.message }
    }
    $observe = if ($toolError) { 'Denied' } else { 'Allowed' }
    if ($toolError -and $text -match 'sentinel') {
        $bySentinel++
        Write-Host ("{0,-12} {1}" -f '[SENTINEL]', $element.Line) -ForegroundColor Yellow
        Write-Host '             blocked by the Sentinel (agent restricted after several denials), not by the syntactic wall' -ForegroundColor DarkGray
        continue
    }
    $ok = ($observe -eq $element.Expected)
    if ($ok) { $compliant++ }
    $mark = if ($ok) { '[OK]' } else { '[GAP]' }
    $color = if ($ok) { 'Green' } else { 'Red' }
    Write-Host ("{0,-12} expected={1,-8} observed={2,-8} {3}" -f $mark, $element.Expected, $observe, $element.Line) -ForegroundColor $color
    if ($toolError) {
        if ($text.Length -gt 150) { $text = $text.Substring(0, 150) + '...' }
        Write-Host "             reason: $text" -ForegroundColor DarkGray
    }
}
Write-Host "`n$compliant / $($lines.Count) as expected ($bySentinel blocked by the Sentinel)." -ForegroundColor Yellow
