#Requires -Version 7.0
<#
.SYNOPSIS
    MIThrandir test client: replays the exact sequence of an MCP client (initialize, initialized, tools/list, tools/call).

.EXAMPLE
    .\Test-MIThrandir.ps1
    .\Test-MIThrandir.ps1 -Url http://MITHRANDIR-01:8765/mcp -Token MyToken
    .\Test-MIThrandir.ps1 -Tool Get-VIServer
    .\Test-MIThrandir.ps1 -Tool Get-VM -Arguments @{ Name = 'TST-*'; Limit = 5 }
    .\Test-MIThrandir.ps1 -Tool Invoke-PowerCLI -Arguments @{ Line = "Get-Cluster CL-TEST | Get-VMHost | Select-Object Name, ConnectionState, Version" }
    .\Test-MIThrandir.ps1 -Tool Invoke-PowerCLI -Arguments @{ Line = 'Get-VM | ForEach-Object { Remove-VM $_ }' }   # must be refused

    Administration console from PowerShell (Windows authentication):
    Invoke-RestMethod http://MITHRANDIR-01:8766/api/state -UseDefaultCredentials
#>
[CmdletBinding()]
param(
    [string]$Url = 'http://localhost:8765/mcp',
    [string]$Token = '',
    [string]$Tool = 'Get-MIThrandirTime',
    [hashtable]$Arguments = @{}
)

$ErrorActionPreference = 'Stop'
$counter = 0
$headers = @{ 'Content-Type' = 'application/json'; 'Accept' = 'application/json, text/event-stream' }
if ($Token) { $headers['Authorization'] = "Bearer $Token" }

function Send-Mcp {
    param([string]$Method, [hashtable]$Params = @{}, [switch]$Notification)
    $script:counter++
    $message = @{ jsonrpc = '2.0'; method = $Method; params = $Params }
    if (-not $Notification) { $message.id = $script:counter }
    $body = $message | ConvertTo-Json -Depth 10 -Compress
    Write-Host "`n>>> $Method" -ForegroundColor Cyan
    Write-Host $body -ForegroundColor DarkGray
    $response = Invoke-WebRequest -Uri $Url -Method Post -Headers $headers -Body $body -SkipHttpErrorCheck
    Write-Host "<<< HTTP $($response.StatusCode)" -ForegroundColor Green
    $idSession = $response.Headers['Mcp-Session-Id']
    if ($idSession) { $headers['Mcp-Session-Id'] = [string]$idSession; Write-Host "    session: $idSession" -ForegroundColor DarkGray }
    if ($response.Content) {
        $object = $response.Content | ConvertFrom-Json -Depth 20
        Write-Host ($object | ConvertTo-Json -Depth 20)
        return $object
    }
}

Send-Mcp -Method 'initialize' -Params @{
    protocolVersion = '2025-06-18'
    capabilities    = @{}
    clientInfo      = @{ name = 'Test-MIThrandir'; version = '0.1' }
} | Out-Null

Send-Mcp -Method 'notifications/initialized' -Notification | Out-Null

$list = Send-Mcp -Method 'tools/list'
Write-Host "`nExposed tools: $(($list.result.tools | ForEach-Object { $_.name }) -join ', ')" -ForegroundColor Yellow

Send-Mcp -Method 'tools/call' -Params @{ name = $Tool; arguments = $Arguments } | Out-Null
