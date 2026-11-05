<#
.SYNOPSIS
    Local MCP relay for MIThrandir: the agent (any MCP client over "stdio") launches it on the user's
    workstation; it forwards each message to MIThrandir with the session's Windows authentication (Kerberos or NTLM).

.DESCRIPTION
    Why: a command-line agent calls MIThrandir over HTTP without saying who is using it. Launched by the agent,
    this relay runs UNDER THE PERSON'S WINDOWS SESSION: MIThrandir receives their AD account via Kerberos,
    with no password or token stored on the workstation, and applies rules per account and per AD group.

    Protocol: MCP "stdio" (one JSON-RPC message per line on standard input, one response per line on
    standard output) on the agent side; MCP "Streamable HTTP" on the MIThrandir side, at http(s)://<mithrandir>:8765/mcp-windows/.
    Nothing but JSON-RPC is written to standard output; service messages go to standard error.

    Registration in the MCP client (once, on the workstation): declare a stdio server named mithrandir with the command
        pwsh -NoProfile -ExecutionPolicy Bypass -File C:\Tools\MIThrandir\MIThrandir-Relay.ps1 -Url http://mithrandir-01:8765/mcp-windows/

.PARAMETER Url
    Address of MIThrandir's authenticated entry point (ending with /mcp-windows/).

.PARAMETER DelaySeconds
    Maximum time for a request to MIThrandir (PowerCLI lines can take a while).
#>
param(
    [Parameter(Mandatory)][string]$Url,
    [int]$DelaySeconds = 300
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$encoding = [System.Text.UTF8Encoding]::new($false)
[Console]::InputEncoding = $encoding
[Console]::OutputEncoding = $encoding
$entry = [System.IO.StreamReader]::new([Console]::OpenStandardInput(), $encoding)
$output = [System.IO.StreamWriter]::new([Console]::OpenStandardOutput(), $encoding)
$output.AutoFlush = $true
$output.NewLine = "`n"

function Write-Service([string]$Text) { [Console]::Error.WriteLine("[MIThrandir-Relay] $Text") }

# HTTP client with the Windows session credentials (Negotiate: Kerberos, otherwise NTLM)
$handler = [System.Net.Http.HttpClientHandler]::new()
$handler.UseDefaultCredentials = $true
$handler.PreAuthenticate = $true
$client = [System.Net.Http.HttpClient]::new($handler)
$client.Timeout = [TimeSpan]::FromSeconds($DelaySeconds)
$idSession = $null
$initializeLine = $null   # V4.8.1: replayed if MIThrandir restarted (HTTP 404 on unknown session)

function Send-ToMIThrandir([string]$Body, [string]$Session) {
    $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Post, $Url)
    $request.Content = [System.Net.Http.StringContent]::new($Body, $encoding, 'application/json')
    [void]$request.Headers.TryAddWithoutValidation('Accept', 'application/json, text/event-stream')
    if ($Session) { [void]$request.Headers.TryAddWithoutValidation('Mcp-Session-Id', $Session) }
    return $client.SendAsync($request).GetAwaiter().GetResult()
}

function Write-JsonRpcError($Id, [int]$Code, [string]$Message) {
    if ($null -eq $Id) { return }
    $output.WriteLine((@{ jsonrpc = '2.0'; id = $Id; error = @{ code = $Code; message = $Message } } | ConvertTo-Json -Compress -Depth 5))
}

Write-Service "relay to $Url for $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
while ($null -ne ($line = $entry.ReadLine())) {
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    $id = $null
    try { $message = $line | ConvertFrom-Json -AsHashtable; if ($message.ContainsKey('id')) { $id = $message.id } } catch { Write-Service "unreadable message ignored"; continue }
    try {
        if ([string]$message.method -eq 'initialize') { $initializeLine = $line; $idSession = $null }
        $response = Send-ToMIThrandir -Body $line -Session $idSession
        if ([int]$response.StatusCode -eq 404 -and $idSession -and $initializeLine) {
            # MIThrandir restarted: open a new session transparently for the client, then replay the message
            Write-Service 'session unknown to MIThrandir (restart): reinitializing'
            $init = Send-ToMIThrandir -Body $initializeLine -Session $null
            $initValues = $null; $idSession = $null
            if ($init.Headers.TryGetValues('Mcp-Session-Id', [ref]$initValues)) { $idSession = @($initValues)[0] }
            [void](Send-ToMIThrandir -Body '{"jsonrpc":"2.0","method":"notifications/initialized"}' -Session $idSession)
            # Tell the client that the tool list may have changed (new MIThrandir version)
            $output.WriteLine('{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}')
            $response = Send-ToMIThrandir -Body $line -Session $idSession
        }
        $valueList = $null
        if ($response.Headers.TryGetValues('Mcp-Session-Id', [ref]$valueList)) { $idSession = @($valueList)[0] }
        $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        if ([int]$response.StatusCode -eq 401) { Write-JsonRpcError $id -32001 "MIThrandir denies the Windows authentication of this workstation: $body"; continue }
        if (-not $response.IsSuccessStatusCode -and [string]::IsNullOrWhiteSpace($body)) { Write-JsonRpcError $id -32002 "MIThrandir answered HTTP $([int]$response.StatusCode)"; continue }
        if ([string]::IsNullOrWhiteSpace($body)) { continue }   # notification accepted (HTTP 202)
        $type = if ($response.Content.Headers.ContentType) { $response.Content.Headers.ContentType.MediaType } else { '' }
        if ($type -eq 'text/event-stream') {
            foreach ($l in ($body -split "`r?`n")) { if ($l.StartsWith('data:')) { $output.WriteLine($l.Substring(5).Trim()) } }
        }
        else {
            # One JSON-RPC response per line. In valid JSON, line breaks are only formatting
            # (those inside strings are escaped as \n): remove them without reinterpreting the values.
            $output.WriteLine(($body -replace '\r?\n\s*', ''))
        }
    }
    catch {
        Write-Service "failure: $($_.Exception.Message)"
        Write-JsonRpcError $id -32003 "MIThrandir unreachable from the relay: $($_.Exception.Message)"
    }
}
$client.Dispose()
