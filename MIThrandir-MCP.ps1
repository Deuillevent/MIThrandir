#Requires -Version 7.0
<#
.SYNOPSIS
    MIThrandir: multi-vCenter MCP gateway, full read-only PowerCLI, double wall (AST + sandbox),
    administration console (versioned policies, agents, log) and SIEM export (Splunk HEC, syslog).

.DESCRIPTION
    MCP server to register in the llama-server WebUI (Settings > MCP > Add New Server) or in
    any MCP Streamable HTTP client. Protocol: JSON-RPC 2.0 over HTTP POST, /mcp endpoint.
    Methods: initialize, notifications/initialized, ping, tools/list, tools/call.

    Files:
      MIThrandir.config.psd1   listener, client authentication, vCenter list (credential and thumbprint per vCenter)
      Policy.psd1        rules (levels, scope, quotas, time window, per-agent rights)
      Policy.ps1         policy engine (Test-Policy, evaluated BEFORE any execution)
      Connection-VCenter.ps1 one DPAPI-encrypted credential and one pinned certificate per vCenter, reconnection
      Sandbox.ps1         separate runspace: PowerCLI connected, cmdlets outside the list invisible, ConstrainedLanguage, timeout
      Validation-AST.ps1    syntactic validation of each PowerCLI line before execution
      Catalog.ps1         Invoke-PowerCLI + typed tools generated from the installed cmdlets
      Journal.ps1           local log, in-memory log for the console, counters, asynchronous Splunk/syslog export
      Console.ps1           administration console (separate port, Windows authentication, AD groups)
      policies\           policy store: active.json + history\vNNNNN.json (history)

.PARAMETER ConfigFile
    Path of the configuration file. Default: MIThrandir.config.psd1 next to the script.

.PARAMETER WithVCenter
    Connects the vCenter and exposes the PowerCLI tools. Without this switch, only Get-MIThrandirTime is exposed.

.PARAMETER SaveCredential
    Prompts for the service account of each vCenter (or only the vCenter named by -VCenter), encrypts it (DPAPI,
    current user + machine) into the block's CredentialFile (credential file), then exits. To be run as the account that operates MIThrandir.

.PARAMETER ShowCertificate
    Displays the thumbprint and subject of the certificate presented by each vCenter (or by -VCenter), then exits.
    The thumbprints must be copied into CertificateThumbprint (certificate thumbprint) of each block.

.PARAMETER VCenter
    Short name of a vCenter from the configuration, to restrict -SaveCredential or -ShowCertificate to it.

.PARAMETER AcceptAnyCertificate
    Does not check the thumbprint of any vCenter certificate. Reserved for tests.

.PARAMETER Address, Port, AllowedIps, Token
    Override the configuration values for this run.

.EXAMPLE
    .\MIThrandir-MCP.ps1 -ShowCertificate
    .\MIThrandir-MCP.ps1 -SaveCredential
    .\MIThrandir-MCP.ps1 -SaveCredential -VCenter vc-prod-1
    .\MIThrandir-MCP.ps1 -WithVCenter
    .\MIThrandir-MCP.ps1 -WithVCenter -AcceptAnyCertificate -Address localhost
#>
[CmdletBinding()]
param(
    [string]$ConfigFile = '',
    [switch]$WithVCenter,
    [switch]$SaveCredential,
    [switch]$ShowCertificate,
    [switch]$AcceptAnyCertificate,
    [string]$VCenter = '',
    [string]$Address = '',
    [int]$Port = 0,
    [string[]]$AllowedIps = @(),
    [string]$Token = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
$Script:SupportedProtocolVersions = @('2025-06-18', '2025-03-26', '2024-11-05')
$Script:DefaultProtocolVersion      = '2025-06-18'
$Script:ServerInfo = @{
    name    = 'mithrandir'
    title   = 'MIThrandir (0.49.0)'
    version = '0.49.0'
}
$Script:RootPath   = $PSScriptRoot
$Script:JournalPath  = Join-Path $PSScriptRoot 'journal'
$Script:JournalFile = Join-Path $Script:JournalPath ("mithrandir-{0}.jsonl" -f (Get-Date -Format 'yyyyMMdd'))
$Script:Sessions       = @{}

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
function Resolve-RelativePath {
    param([string]$Path)
    if ([System.IO.Path]::IsPathRooted($Path)) { return $Path }
    return Join-Path $Script:RootPath $Path
}

if ([string]::IsNullOrEmpty($ConfigFile)) { $ConfigFile = Join-Path $Script:RootPath 'MIThrandir.config.psd1' }
if (-not (Test-Path $ConfigFile)) { throw "Configuration not found: $ConfigFile" }
$Script:Config = Import-PowerShellDataFile -Path $ConfigFile

# Command-line overrides
if ($Address)                { $Script:Config.Address = $Address }
if ($Port -gt 0)             { $Script:Config.Port = $Port }
if ($PSBoundParameters.ContainsKey('AllowedIps')) { $Script:Config.AllowedIps = $AllowedIps }
if ($PSBoundParameters.ContainsKey('Token'))        { $Script:Config.Token = $Token }
foreach ($key in @('Address', 'Port', 'AllowedIps', 'Token')) {
    if (-not $Script:Config.ContainsKey($key)) { throw "Configuration: mandatory key missing: $key" }
}
$Script:Config.AllowedIps = @($Script:Config.AllowedIps)
if (-not $Script:Config.ContainsKey('PolicyStore')) { $Script:Config.PolicyStore = 'policies' }
if (-not $Script:Config.ContainsKey('Console')) { $Script:Config.Console = @{ Active = $false } }
if (-not $Script:Config.ContainsKey('StrictSessions')) { $Script:Config.StrictSessions = $true }
$Script:WithActiveVCenter = [bool]$WithVCenter

# ---------------------------------------------------------------------------
# Loading internal modules
# ---------------------------------------------------------------------------
foreach ($file in @('Journal.ps1', 'Policy.ps1', 'Connection-VCenter.ps1', 'Sandbox.ps1', 'Validation-AST.ps1', 'Inventory.ps1', 'Scope.ps1', 'Sentinel.ps1', 'Identity.ps1', 'Scripts.ps1', 'Catalog.ps1', 'Console.ps1')) {
    $path = Join-Path $Script:RootPath $file
    if (-not (Test-Path $path)) { throw "File not found: $path" }
    . $path
}

$psd1Path = if ($Script:Config.ContainsKey('PolicyFile')) { Resolve-RelativePath $Script:Config.PolicyFile } else { Join-Path $Script:RootPath 'Policy.psd1' }
Initialize-Policy -RepositoryPath (Resolve-RelativePath $Script:Config.PolicyStore) -Psd1Path $psd1Path
Initialize-Sentinel
# V4.5: vCenter list read from the store managed by the console (imported from MIThrandir.config.psd1 at first startup)
Initialize-VCenterStore

# ---------------------------------------------------------------------------
# Utility modes: register credentials, display certificates
# ---------------------------------------------------------------------------
$targetBlocks = @(if ($VCenter) { @(Get-VcenterBlock -Name $VCenter) } else { @($Script:Config.VCenters) })
if ($SaveCredential) {
    Write-Host "Saving credentials (DPAPI, $env:USERDOMAIN\$env:USERNAME on $env:COMPUTERNAME). Cancel a dialog box to skip a vCenter." -ForegroundColor Cyan
    foreach ($block in $targetBlocks) { Save-VcenterCredential -Block $block }
    exit 0
}

if ($ShowCertificate) {
    foreach ($block in $targetBlocks) {
        $portVCenter = if ($block.ContainsKey('Port') -and $block.Port) { [int]$block.Port } else { 443 }
        Write-Host ''
        Write-Host "[$($block.Name)] $($block.Server):$portVCenter" -ForegroundColor Cyan
        try {
            $certificate = Get-CertificateThumbprint -HostName $block.Server -Port $portVCenter
            Write-Host "  Subject     : $($certificate.Subject)"
            Write-Host "  Issuer      : $($certificate.Issuer)"
            Write-Host "  Expires on  : $($certificate.ExpiresOn.ToString('yyyy-MM-dd'))"
            Write-Host "  Self-signed : $($certificate.SelfSigned)"
            Write-Host "  Thumbprint  : $($certificate.Thumbprint)" -ForegroundColor Yellow
            $expected = if ($block.ContainsKey('CertificateThumbprint')) { ([string]$block.CertificateThumbprint).Replace(':', '').ToUpperInvariant() } else { '' }
            if ($expected -eq $certificate.Thumbprint) { Write-Host '  Matches the configuration' -ForegroundColor Green }
            elseif ($expected) { Write-Host "  DIFFERENT from the configuration ($expected)" -ForegroundColor Red }
            else { Write-Host "  To copy into MIThrandir.config.psd1: CertificateThumbprint = '$($certificate.Thumbprint)'" -ForegroundColor DarkGray }
        }
        catch { Write-Host "  Unreachable: $($_.Exception.Message)" -ForegroundColor Red }
    }
    Write-Host ''
    exit 0
}

# ---------------------------------------------------------------------------
# Sandbox and vCenter connections
# ---------------------------------------------------------------------------
$Script:AcceptAnyCertificate = [bool]$AcceptAnyCertificate
if ($WithVCenter) {
    if (-not (Get-Module -ListAvailable -Name VMware.VimAutomation.Core)) {
        throw 'VMware.PowerCLI module missing. Install it offline in $env:ProgramFiles\PowerShell\Modules (see README).'
    }
    Initialize-TableVCenters
    $modules = @(if ($Script:Config.ContainsKey('PowerCliModules')) { @($Script:Config.PowerCliModules) } else { @('VMware.VimAutomation.Core', 'VMware.VimAutomation.Storage', 'VMware.VimAutomation.Vds', 'VMware.VimAutomation.Cis.Core') })
    Initialize-Sandbox -PowerCliModules $modules

    $tolerate = $Script:Config.ContainsKey('TolerateUnreachableVCenter') -and $Script:Config.TolerateUnreachableVCenter
    foreach ($name in @($Script:VcenterConnections.Keys)) {
        $ok = Connect-VcenterInSandbox -Name $name -AcceptAnyCertificate:$AcceptAnyCertificate
        if (-not $ok -and -not $tolerate) { throw "Startup denied: $name unreachable and TolerateUnreachableVCenter = `$false" }
    }
    $connected = @($Script:VcenterConnections.Values | Where-Object { $_.Connection })
    if ($Script:VcenterConnections.Count -eq 0) {
        Write-Journal -Level 'ALERT' -Message 'No vCenter declared: add them from the console (Global settings, vCenters)'
    }
    elseif ($connected.Count -eq 0 -and -not $tolerate) { throw 'No vCenter connected, stopping.' }
    Write-Journal -Level 'INFO' -Message "vCenters connected: $($connected.Count) of $($Script:VcenterConnections.Count)" -Data @{ connected = @($connected | ForEach-Object { $_.Name }) }

    # From here on, no command outside the allowlist is visible in the sandbox, and the language is constrained
    Lock-Sandbox

    # Automatic inventory in a background task (runspace and sessions separate from the sandbox)
    Start-AutomaticInventory -AcceptAnyCertificate:$AcceptAnyCertificate
}

$Script:Catalog = Get-ToolCatalog -WithVCenter:$WithVCenter

# ---------------------------------------------------------------------------
# HTTP / JSON-RPC utilities
# ---------------------------------------------------------------------------
function New-JsonRpcResponse {
    param([object]$Id, [object]$Result)
    return @{ jsonrpc = '2.0'; id = $Id; result = $Result }
}

function New-JsonRpcError {
    param([object]$Id, [int]$Code, [string]$Message, [object]$Data = $null)
    $errorInfo = @{ code = $Code; message = $Message }
    if ($null -ne $Data) { $errorInfo.data = $Data }
    return @{ jsonrpc = '2.0'; id = $Id; error = $errorInfo }
}

function Test-AllowedOrigin {
    <#
    V4.6: a browser origin is accepted only if it appears in AllowedOrigins (allowed origins, config).
    Wildcard patterns accepted (e.g. 'http://llm-webui.example.local', 'https://*.example.local').
    Empty AllowedOrigins = no third-party web page (safe default behavior); '*' = everything (avoid in production).
    #>
    param([string]$Origin)
    if ([string]::IsNullOrEmpty($Origin)) { return $true }   # no-browser client (no Origin header)
    $patterns = @(if ($Script:Config.ContainsKey('AllowedOrigins')) { @($Script:Config.AllowedOrigins) } else { @() })
    foreach ($pattern in $patterns) { if ($pattern -eq '*' -or $Origin -like $pattern) { return $true } }
    return $false
}

function Add-CorsHeaders {
    param([System.Net.HttpListenerResponse]$Response, [string]$Origin)
    # The llama-server WebUI runs in a browser: without these headers, the browser rejects the response.
    # V4.6: reflect ONLY the allowed origins (otherwise a third-party web page opened on an authorized workstation
    # could drive MIThrandir). A no-browser client (without Origin) is not affected.
    $Response.Headers['Access-Control-Allow-Methods']  = 'GET, POST, DELETE, OPTIONS'
    $Response.Headers['Access-Control-Allow-Headers']  = 'Content-Type, Accept, Authorization, Mcp-Session-Id, MCP-Protocol-Version, Last-Event-ID'
    $Response.Headers['Access-Control-Expose-Headers'] = 'Mcp-Session-Id, MCP-Protocol-Version'
    $Response.Headers['Access-Control-Max-Age']        = '600'
    if (-not [string]::IsNullOrEmpty($Origin) -and (Test-AllowedOrigin -Origin $Origin)) {
        $Response.Headers['Access-Control-Allow-Origin'] = $Origin
        $Response.Headers['Vary'] = 'Origin'
    }
    # Origin absent or not allowed: no Access-Control-Allow-Origin (the browser blocks reading the response)
}

function Send-Body {
    param(
        [System.Net.HttpListenerResponse]$Response,
        [int]$Status,
        [string]$Body = '',
        [string]$ContentType = 'application/json; charset=utf-8'
    )
    # V4.8.1: the client (console browser, relay, llama-server) may have left while the loop
    # was busy with a long call (e.g. Get-VM | Get-Snapshot on 3 vCenters, ~40 s). Writing to a closed
    # connection raises "The specified network name is no longer available" (Win32 error 64): this is not a failure,
    # so drop the response cleanly and log it as INFO instead of raising an ERROR with a stack trace.
    try {
        $Response.StatusCode = $Status
        if ([string]::IsNullOrEmpty($Body)) {
            $Response.ContentLength64 = 0
        }
        else {
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($Body)
            $Response.ContentType = $ContentType
            $Response.ContentLength64 = $bytes.Length
            $Response.OutputStream.Write($bytes, 0, $bytes.Length)
        }
        $Response.OutputStream.Close()
    }
    catch {
        if (-not (Test-ClientDisconnected -Error $_.Exception)) { throw }
        try { $Response.Abort() } catch { }
        $Script:UndeliveredResponses++
        try { Write-Journal -Level 'INFO' -Message 'Response not delivered: client disconnected before processing ended' -Data @{ status = $Status; cumulative = $Script:UndeliveredResponses } } catch { }
    }
}

$Script:UndeliveredResponses = 0
function Test-ClientDisconnected {
    <# True if the exception (or an inner exception) indicates an HTTP connection closed on the client side. #>
    param([System.Exception]$errorInfo)
    # 64 = ERROR_NETNAME_DELETED, 995 = ERROR_OPERATION_ABORTED, 1229 = ERROR_CONNECTION_INVALID,
    # 1236 = ERROR_CONNECTION_ABORTED, 10053 / 10054 = WSAECONNABORTED / WSAECONNRESET
    $codes = @(64, 995, 1229, 1236, 10053, 10054)
    $e = $errorInfo
    while ($e) {
        if ($e -is [System.Net.HttpListenerException] -and $e.ErrorCode -in $codes) { return $true }
        if ($e -is [System.ObjectDisposedException]) { return $true }
        if ($e -is [System.IO.IOException] -and $e.InnerException -is [System.Net.HttpListenerException]) { return $true }
        $e = $e.InnerException
    }
    return $false
}

function Test-Authorization {
    param([System.Net.HttpListenerRequest]$Request)
    $ipSource = (Get-RequestIp -Request $Request)
    if ($Script:Config.AllowedIps.Count -gt 0 -and $ipSource -notin $Script:Config.AllowedIps) {
        return @{ Ok = $false; Reason = "Source IP not allowed: $ipSource" }
    }
    if (-not [string]::IsNullOrEmpty($Script:Config.Token)) {
        $header = $Request.Headers['Authorization']
        if ($header -ne "Bearer $($Script:Config.Token)") {
            return @{ Ok = $false; Reason = 'Bearer token missing or invalid' }
        }
    }
    return @{ Ok = $true; Reason = '' }
}

# ---------------------------------------------------------------------------
# MCP method handling
# ---------------------------------------------------------------------------
function Invoke-McpMethod {
    param(
        [hashtable]$Message,
        [System.Net.HttpListenerRequest]$Request,
        [System.Net.HttpListenerResponse]$Response
    )
    $id       = if ($Message.ContainsKey('id')) { $Message.id } else { $null }
    $method  = [string]$Message.method
    $params   = if ($Message.ContainsKey('params') -and $null -ne $Message.params) { $Message.params } else { @{} }
    $ipSource = (Get-RequestIp -Request $Request)

    switch ($method) {

        'initialize' {
            $versionClient = if ($params.ContainsKey('protocolVersion')) { [string]$params['protocolVersion'] } else { '' }
            $infoClient    = if ($params.ContainsKey('clientInfo')) { $params['clientInfo'] } else { @{} }
            $chosenVersion = if ($versionClient -in $Script:SupportedProtocolVersions) { $versionClient } else { $Script:DefaultProtocolVersion }
            $idSession = [guid]::NewGuid().ToString('N')
            $Script:Sessions[$idSession] = @{ Creation = Get-Date; IP = $ipSource; Client = $infoClient }
            $Response.Headers['Mcp-Session-Id'] = $idSession
            Write-Journal -Level 'INFO' -Message 'initialize' -Data @{ ip = $ipSource; versionClient = $versionClient; chosenVersion = $chosenVersion; client = $infoClient; session = $idSession }
            return New-JsonRpcResponse -Id $id -Result @{
                protocolVersion = $chosenVersion
                capabilities    = @{ tools = @{ listChanged = $false } }
                serverInfo      = $Script:ServerInfo
                instructions    = 'MIThrandir V4: read-only PowerCLI on several vCenters. Start with Get-VIServer. Invoke-PowerCLI accepts a complete PowerCLI line with a pipeline; the Get-* tools have the exact PowerCLI parameters. For bulk reads (thousands of VMs, counts per cluster, folder or tag), prefer Get-MIThrandirInventory, which reads the cache refreshed by MIThrandir. Each call is validated by a policy before execution.'
            }
        }

        'notifications/initialized' {
            Write-Journal -Level 'INFO' -Message 'notifications/initialized' -Data @{ ip = $ipSource }
            return $null   # notification: no response body (HTTP 202)
        }

        'ping' {
            return New-JsonRpcResponse -Id $id -Result @{}
        }

        'tools/list' {
            $tools = @($Script:Catalog | ForEach-Object {
                @{ name = $_.Name; title = $_.Title; description = $_.Description; inputSchema = $_.InputSchema }
            })
            Write-Journal -Level 'INFO' -Message 'tools/list' -Data @{ ip = $ipSource; quantity = $tools.Count }
            return New-JsonRpcResponse -Id $id -Result @{ tools = $tools }
        }

        'tools/call' {
            $toolName  = if ($params.ContainsKey('name')) { [string]$params['name'] } else { '' }
            $arguments = if ($params.ContainsKey('arguments') -and $null -ne $params['arguments']) { [hashtable]$params['arguments'] } else { @{} }
            $tool = $Script:Catalog | Where-Object { $_.Name -eq $toolName } | Select-Object -First 1

            if ($null -eq $tool) {
                Write-Journal -Level 'DENIED' -Message "Unknown tool: $toolName" -Data @{ ip = $ipSource }
                return New-JsonRpcError -Id $id -Code -32602 -Message "Unknown tool: $toolName"
            }

            # ----- POLICY ENFORCEMENT POINT: before any execution -----
            $decision = Test-Policy -Tool $tool -Arguments $arguments -IPSource $ipSource
            if (-not $decision.Allowed) {
                Write-Journal -Level 'DENIED' -Message "Policy: denial of $toolName" -Data @{ ip = $ipSource; arguments = $arguments; reason = $decision.Reason }
                return New-JsonRpcResponse -Id $id -Result @{
                    content = @(@{ type = 'text'; text = "Action denied by the MIThrandir policy: $($decision.Reason)$(Get-SentinelWarning -IP (Get-AgentKey -IP $ipSource))" })
                    isError = $true
                }
            }

            Write-Journal -Level 'CALL' -Message "Execution of $toolName" -Data @{ ip = $ipSource; arguments = $arguments }
            try {
                $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                # PowerCLI objects sometimes have null properties (disconnected host, orphaned VM):
                # disable strict mode for the tool execution only; the server itself stays strict.
                Set-StrictMode -Off
                $toolDecision = if ($decision.ContainsKey('Decision')) { $decision.Decision } else { $null }
                $result = & $tool.Action $arguments @{ IPSource = $ipSource; ToolName = $toolName; Decision = $toolDecision }
                Set-StrictMode -Version Latest
                $stopwatch.Stop()
                $text = if ($result -is [string]) { $result } else { $result | ConvertTo-Json -Depth 8 }
                $maxSize = [int](Get-Global).MaxOutputSize
                if ($text.Length -gt $maxSize) { $text = $text.Substring(0, $maxSize) + "`n... [output truncated at $maxSize characters by MIThrandir; refine the request or use Select-Object]" }
                Write-Journal -Level 'INFO' -Message "Completed $toolName" -Data @{ ip = $ipSource; durationMs = $stopwatch.ElapsedMilliseconds; size = $text.Length }
                return New-JsonRpcResponse -Id $id -Result @{
                    content = @(@{ type = 'text'; text = ($text + (Get-SentinelWarning -IP (Get-AgentKey -IP $ipSource))) })
                    isError = $false
                }
            }
            catch {
                Write-Journal -Level 'ERROR' -Message "Failure of $toolName - $($_.Exception.Message)" -Data @{ ip = $ipSource }
                return New-JsonRpcResponse -Id $id -Result @{
                    content = @(@{ type = 'text'; text = "Error while executing $toolName - $($_.Exception.Message)" })
                    isError = $true
                }
            }
        }

        default {
            if ($method -like 'notifications/*') { return $null }
            Write-Journal -Level 'DENIED' -Message "Unsupported method: $method" -Data @{ ip = $ipSource }
            return New-JsonRpcError -Id $id -Code -32601 -Message "Unsupported method: $method"
        }
    }
}

# ---------------------------------------------------------------------------
# HTTP request handling
# ---------------------------------------------------------------------------
function Invoke-HttpRequest {
    param([System.Net.HttpListenerContext]$Context)
    $request = $Context.Request
    $response = $Context.Response
    $path  = $request.Url.AbsolutePath.TrimEnd('/')
    Add-CorsHeaders -Response $response -Origin $request.Headers['Origin']

    try {
        # Browser CORS preflight: always accepted, without authentication
        if ($request.HttpMethod -eq 'OPTIONS') { Send-Body -Response $response -Status 204; return }

        # Health page, handy to check that the service is listening
        if ($path -eq '' -or $path -eq '/health') {
            $state = @{ service = $Script:ServerInfo.name; version = $Script:ServerInfo.version; tools = @($Script:Catalog.Name); vcenter = [bool]$WithVCenter; policy = $Script:PolicyMeta.version; suspended = $Script:GatewayState.suspended }
            Send-Body -Response $response -Status 200 -Body ($state | ConvertTo-Json -Depth 3)
            return
        }

        # V4.6: OpenMetrics metrics (scraped by Prometheus or by the prometheus receiver of an OpenTelemetry collector).
        # Read-only, no MCP token; filterable by IP (Metrics.AllowedIps or, by default, the global AllowedIps).
        if ($path -eq '/metrics') {
            $cfgMet = if ($Script:Config.ContainsKey('Metrics')) { $Script:Config.Metrics } else { @{ Active = $true } }
            if (-not $cfgMet.Active) { Send-Body -Response $response -Status 404 -Body ''; return }
            $ipMet = (Get-RequestIp -Request $request)
            $metList = @(if ($cfgMet.ContainsKey('AllowedIps') -and @($cfgMet.AllowedIps).Count -gt 0) { $cfgMet.AllowedIps } else { $Script:Config.AllowedIps })
            if ($metList.Count -gt 0 -and $ipMet -notin $metList -and $ipMet -notin @('127.0.0.1', '::1')) {
                Send-Body -Response $response -Status 403 -Body ''; return
            }
            Send-Body -Response $response -Status 200 -Body (Get-OpenMetricsMetrics) -ContentType 'application/openmetrics-text; version=1.0.0; charset=utf-8'
            return
        }

        if ($path -notin @('/mcp', '/mcp-windows')) { Send-Body -Response $response -Status 404 -Body '{"error":"Unknown endpoint, use /mcp (or /mcp-windows/ with Windows authentication)"}'; return }

        $authorization = Test-Authorization -Request $request
        if (-not $authorization.Ok) {
            Write-Journal -Level 'DENIED' -Message $authorization.Reason -Data @{ ip = (Get-RequestIp -Request $request) }
            Send-Body -Response $response -Status 401 -Body '{"error":"Not allowed"}'
            return
        }

        # V4.6: a request carrying a no-authorized browser origin is refused (anti-CSRF; /mcp is anonymous)
        $requestOrigin = $request.Headers['Origin']
        if (-not (Test-AllowedOrigin -Origin $requestOrigin)) {
            Write-Journal -Level 'DENIED' -Message "Origin not allowed: $requestOrigin" -Data @{ ip = (Get-RequestIp -Request $request); origin = $requestOrigin }
            Send-Body -Response $response -Status 403 -Body '{"error":"Origin not allowed"}'
            return
        }

        # Identity of the person (Windows authentication or signed assertion from a trusted relay)
        $identity = Resolve-RequestIdentity -Context $Context -Path $path
        if (-not $identity.Ok) {
            Write-Journal -Level 'DENIED' -Message "Identity denied: $($identity.Reason)" -Data @{ ip = (Get-RequestIp -Request $request); reason = $identity.Reason }
            Send-Body -Response $response -Status 401 -Body (@{ error = "Identity denied: $($identity.Reason)" } | ConvertTo-Json -Compress)
            return
        }

        switch ($request.HttpMethod) {
            'GET' {
                # The Streamable HTTP transport allows a server -> client SSE stream on GET.
                # MIThrandir never sends unsolicited messages: 405 is the response provided for by the specification.
                Send-Body -Response $response -Status 405
            }
            'DELETE' {
                $idSession = $request.Headers['Mcp-Session-Id']
                if ($idSession -and $Script:Sessions.ContainsKey($idSession)) { $Script:Sessions.Remove($idSession) }
                Send-Body -Response $response -Status 200
            }
            'POST' {
                $reader = New-Object System.IO.StreamReader($request.InputStream, $request.ContentEncoding)
                $body = $reader.ReadToEnd()
                $reader.Close()

                $message = $null
                try { $message = $body | ConvertFrom-Json -AsHashtable -Depth 20 }
                catch {
                    Send-Body -Response $response -Status 400 -Body ((New-JsonRpcError -Id $null -Code -32700 -Message 'Invalid JSON') | ConvertTo-Json -Depth 5)
                    return
                }

                if ($message -is [array]) {
                    # JSON-RPC batches were removed from the 2025-06-18 specification
                    Send-Body -Response $response -Status 400 -Body ((New-JsonRpcError -Id $null -Code -32600 -Message 'JSON-RPC batches not supported') | ConvertTo-Json -Depth 5)
                    return
                }

                # V4.8.1: unknown MCP session (MIThrandir restarted since the client's initialize). Without this check, the
                # client keeps using the tool list obtained before the restart and never sees the new tools.
                # The MCP specification provides for HTTP 404: the client must then redo initialize and then tools/list.
                $idSessionClient = $request.Headers['Mcp-Session-Id']
                if ($Script:Config.StrictSessions -and $message -is [hashtable] -and [string]$message.method -ne 'initialize' -and
                    -not [string]::IsNullOrEmpty($idSessionClient) -and -not $Script:Sessions.ContainsKey($idSessionClient)) {
                    Write-Journal -Level 'INFO' -Message 'Unknown MCP session (older than the MIThrandir startup): the client must reinitialize' -Data @{ ip = (Get-RequestIp -Request $request); method = [string]$message.method; session = $idSessionClient }
                    $idMsg = if ($message.ContainsKey('id')) { $message.id } else { $null }
                    Send-Body -Response $response -Status 404 -Body ((New-JsonRpcError -Id $idMsg -Code -32001 -Message 'Unknown or expired MCP session (MIThrandir restarted): redo initialize') | ConvertTo-Json -Depth 5)
                    return
                }

                $result = Invoke-McpMethod -Message $message -Request $request -Response $response
                if ($null -eq $result) {
                    Send-Body -Response $response -Status 202
                }
                else {
                    Send-Body -Response $response -Status 200 -Body ($result | ConvertTo-Json -Depth 12)
                }
            }
            default { Send-Body -Response $response -Status 405 }
        }
    }
    catch {
        Write-Journal -Level 'ERROR' -Message "Internal error: $($_.Exception.Message)" -Data @{ line = $_.InvocationInfo.ScriptLineNumber }
        try { Send-Body -Response $response -Status 500 -Body ((New-JsonRpcError -Id $null -Code -32603 -Message 'MIThrandir internal error') | ConvertTo-Json -Depth 5) } catch { }
    }
    finally { Reset-CurrentIdentity }
}

# ---------------------------------------------------------------------------
# Main loop: an MCP listener (anonymous, IP/token filter) and a console listener (Windows authentication)
# ---------------------------------------------------------------------------
$Script:McpPrefix = "http://$($Script:Config.Address):$($Script:Config.Port)/"
$mcpListener = New-Object System.Net.HttpListener
$mcpListener.Prefixes.Add($Script:McpPrefix)
$mcpListener.AuthenticationSchemes = [System.Net.AuthenticationSchemes]::Anonymous
# Same port, /mcp-windows/ path: second listener with integrated Windows authentication (local relay MIThrandir-Relay.ps1).
# HTTP.sys routes to the longest prefix; each listener keeps its own authentication scheme.
$mcpWindowsListener = New-Object System.Net.HttpListener
$mcpWindowsListener.Prefixes.Add("$($Script:McpPrefix)mcp-windows/")
$mcpWindowsListener.AuthenticationSchemes = [System.Net.AuthenticationSchemes]::IntegratedWindowsAuthentication

$consoleListener = $null
$consolePrefix = ''
if ($Script:Config.Console.Active) {
    $consoleAddress = if ($Script:Config.Console.ContainsKey('Address') -and $Script:Config.Console.Address) { $Script:Config.Console.Address } else { $Script:Config.Address }
    $portConsole = if ($Script:Config.Console.ContainsKey('Port') -and $Script:Config.Console.Port) { [int]$Script:Config.Console.Port } else { 8766 }
    $schema = if ($Script:Config.Console.ContainsKey('Https') -and $Script:Config.Console.Https) { 'https' } else { 'http' }
    $consolePrefix = "${schema}://${consoleAddress}:${portConsole}/"
    $Script:ConsoleAlertPrefix = $consolePrefix
    $consoleListener = New-Object System.Net.HttpListener
    $consoleListener.Prefixes.Add($consolePrefix)
    $consoleListener.AuthenticationSchemes = [System.Net.AuthenticationSchemes]::IntegratedWindowsAuthentication
}

try { $mcpListener.Start(); $mcpWindowsListener.Start() }
catch {
    Write-Host "Cannot listen on $($Script:McpPrefix): $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "URL reservation (once, as administrator): netsh http add urlacl url=$($Script:McpPrefix) user=`"$env:USERDOMAIN\$env:USERNAME`"" -ForegroundColor Yellow
    exit 1
}
if ($consoleListener) {
    try { $consoleListener.Start() }
    catch {
        $mcpListener.Stop()
        Write-Host "Cannot listen for the console on $consolePrefix : $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "URL reservation: netsh http add urlacl url=$consolePrefix user=`"$env:USERDOMAIN\$env:USERNAME`"" -ForegroundColor Yellow
        exit 1
    }
}

Start-ExportJournal

Write-Journal -Level 'INFO' -Message "MIThrandir 0.49.0 listening on $($Script:McpPrefix)mcp" -Data @{ tools = @($Script:Catalog.Name); vcenter = [bool]$WithVCenter; ipFilter = $Script:Config.AllowedIps; token = (-not [string]::IsNullOrEmpty($Script:Config.Token)); console = $consolePrefix; policy = $Script:PolicyMeta.version }
Write-Host 'Ctrl+C to stop.' -ForegroundColor DarkGray

try {
    $mcpTask = $mcpListener.GetContextAsync()
    $mcpWindowsTask = $mcpWindowsListener.GetContextAsync()
    $consoleTask = if ($consoleListener) { $consoleListener.GetContextAsync() } else { $null }
    while ($mcpListener.IsListening) {
        $tasks = @($mcpTask, $mcpWindowsTask); if ($consoleTask) { $tasks += $consoleTask }
        # Wait in short slices so that Ctrl+C can interrupt cleanly
        $index = [System.Threading.Tasks.Task]::WaitAny($tasks, 500)
        if ($index -lt 0) { continue }
        if ($tasks[$index] -eq $mcpTask) {
            $context = $mcpTask.Result
            $mcpTask = $mcpListener.GetContextAsync()
            try { Invoke-HttpRequest -Context $context } catch { try { Write-Journal -Level 'ERROR' -Message "Request abandoned: $($_.Exception.Message)" } catch { } }
        }
        elseif ($tasks[$index] -eq $mcpWindowsTask) {
            $context = $mcpWindowsTask.Result
            $mcpWindowsTask = $mcpWindowsListener.GetContextAsync()
            try { Invoke-HttpRequest -Context $context } catch { try { Write-Journal -Level 'ERROR' -Message "Request abandoned: $($_.Exception.Message)" } catch { } }
        }
        else {
            $context = $consoleTask.Result
            $consoleTask = $consoleListener.GetContextAsync()
            try { Invoke-ConsoleRequest -Context $context } catch { try { Write-Journal -Level 'ERROR' -Message "Request abandoned: $($_.Exception.Message)" } catch { } }
        }
    }
}
finally {
    Write-Journal -Level 'INFO' -Message 'MIThrandir stopping'
    if ($mcpListener.IsListening) { $mcpListener.Stop() }
    $mcpListener.Close()
    if ($mcpWindowsListener.IsListening) { $mcpWindowsListener.Stop() }
    $mcpWindowsListener.Close()
    if ($consoleListener) { if ($consoleListener.IsListening) { $consoleListener.Stop() }; $consoleListener.Close() }
    if ($WithVCenter -and $Script:Sandbox) {
        try { Unlock-Sandbox; Invoke-RawInSandbox -Script 'Disconnect-VIServer -Server * -Confirm:$false -ErrorAction SilentlyContinue' | Out-Null } catch { }
        $Script:Sandbox.Runspace.Dispose()
        Write-Journal -Level 'INFO' -Message 'Sandbox closed, vCenter sessions ended'
    }
    Stop-AutomaticInventory
    Stop-ExportJournal
}
