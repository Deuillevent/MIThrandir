<#
.SYNOPSIS
    Encrypted credentials and pinned certificates per vCenter (MIThrandir V2). The connections themselves
    are opened in the sandbox (Sandbox.ps1), where the PowerCLI sessions live.
#>

$Script:VcenterConnections = [ordered]@{}   # Name -> @{ Name; Config; Credential; Connection (VIServer or $null); Error }

function Get-VcenterBlock {
    param([Parameter(Mandatory)][string]$Name)
    $block = @($Script:Config.VCenters | Where-Object { $_.Name -eq $Name }) | Select-Object -First 1
    if ($null -eq $block) { throw "vCenter '$Name' missing from the configuration. Known names: $(@($Script:Config.VCenters.Name) -join ', ')" }
    return $block
}

function Save-VcenterCredential {
    param([Parameter(Mandatory)][hashtable]$Block)
    $path = Resolve-RelativePath $Block.CredentialFile
    $credential = Get-Credential -Message "Service account for $($Block.Name) ($($Block.Server)), DPAPI-encrypted for $env:USERDOMAIN\$env:USERNAME on $env:COMPUTERNAME"
    if ($null -eq $credential) { Write-Host "  $($Block.Name) : skipped" -ForegroundColor DarkYellow; return }
    $credential | Export-Clixml -Path $path -Force
    Write-Host "  $($Block.Name) : credential $($credential.UserName) saved in $(Split-Path $path -Leaf)" -ForegroundColor Green
}

function Get-VcenterCredential {
    param([Parameter(Mandatory)][hashtable]$Block)
    $path = Resolve-RelativePath $Block.CredentialFile
    if (-not (Test-Path $path)) { throw "Credential file not found for $($Block.Name): $path. Run MIThrandir-MCP.ps1 -SaveCredential -VCenter $($Block.Name)" }
    try { return Import-Clixml -Path $path }
    catch { throw "Cannot decrypt $path for $($Block.Name) (created by another user or on another machine?): $($_.Exception.Message)" }
}

function Get-CertificateThumbprint {
    param([Parameter(Mandatory)][string]$HostName, [int]$Port = 443)
    $client = $null; $stream = $null
    try {
        $client = [System.Net.Sockets.TcpClient]::new()
        $client.Connect($HostName, $Port)
        $stream = [System.Net.Security.SslStream]::new($client.GetStream(), $false, { param($senderAddress, $certificate, $string, $errors) $true })
        $stream.AuthenticateAsClient($HostName)
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($stream.RemoteCertificate)
        return @{ Thumbprint = $certificate.Thumbprint; Subject = $certificate.Subject; Issuer = $certificate.Issuer; ExpiresOn = $certificate.NotAfter; SelfSigned = ($certificate.Subject -eq $certificate.Issuer) }
    }
    finally {
        if ($stream) { $stream.Dispose() }
        if ($client) { $client.Dispose() }
    }
}

function Test-VcenterCertificate {
    param([Parameter(Mandatory)][hashtable]$Block, [switch]$AcceptAnyCertificate)
    $port = if ($Block.ContainsKey('Port') -and $Block.Port) { [int]$Block.Port } else { 443 }
    $certificate = Get-CertificateThumbprint -HostName $Block.Server -Port $port
    $expected = if ($Block.ContainsKey('CertificateThumbprint')) { ([string]$Block.CertificateThumbprint).Replace(':', '').Replace(' ', '').ToUpperInvariant() } else { '' }
    if ($AcceptAnyCertificate) {
        Write-Journal -Level 'INFO' -Message "Certificate of $($Block.Name) accepted without verification (POC mode)" -Data @{ server = $Block.Server; thumbprint = $certificate.Thumbprint; subject = $certificate.Subject }
        return
    }
    if ([string]::IsNullOrEmpty($expected)) {
        throw ("No CertificateThumbprint for $($Block.Name). The vCenter presents {0} (subject: {1}, self-signed: {2}). Copy the thumbprint into MIThrandir.config.psd1, or run with -AcceptAnyCertificate for a test.") -f $certificate.Thumbprint, $certificate.Subject, $certificate.SelfSigned
    }
    if ($certificate.Thumbprint -ne $expected) { throw "Unexpected certificate for $($Block.Name): presented $($certificate.Thumbprint), expected $expected. Connection denied." }
    Write-Journal -Level 'INFO' -Message "Certificate of $($Block.Name) matches the pinned thumbprint" -Data @{ server = $Block.Server; thumbprint = $certificate.Thumbprint; expiresOn = $certificate.ExpiresOn.ToString('yyyy-MM-dd') }
}

function Initialize-TableVCenters {
    <# Reads all credentials BEFORE the first connection. A missing or unreadable credential no longer blocks startup (V4.5):
       the vCenter is flagged as in error and is fixed from the console (Settings page, vCenters section). #>
    foreach ($block in @($Script:Config.VCenters)) {
        foreach ($key in @('Name', 'Server', 'CredentialFile')) { if (-not $block.ContainsKey($key)) { throw "VCenters configuration: key '$key' missing in a block" } }
        if ($Script:VcenterConnections.Contains($block.Name)) { throw "VCenters configuration: duplicate name: $($block.Name)" }
        $entry = @{ Name = $block.Name; Config = $block; Credential = $null; Connection = $null; Error = '' }
        try { $entry.Credential = Get-VcenterCredential -Block $block }
        catch {
            $entry.Error = $_.Exception.Message
            Write-Journal -Level 'ERROR' -Message "Credential of $($block.Name) unavailable: $($_.Exception.Message)" -Data @{ vcenter = $block.Name }
        }
        $Script:VcenterConnections[$block.Name] = $entry
    }
}

# ---------------------------------------------------------------------------
# V4.5 : vCenter list managed from the console
# Store: <VCenterStore>\vcenters.json (active) + history\vNNNNN.json (history); credentials: <VCenterStore>\Credential-<name>.xml
# On first startup, the VCenters block of MIThrandir.config.psd1 is imported as is, then the psd1 is no longer read for vCenters.
# ---------------------------------------------------------------------------
$Script:VCenterStore = $null

function Initialize-VCenterStore {
    $folder = Resolve-RelativePath $(if ($Script:Config.ContainsKey('VCenterStore') -and $Script:Config.VCenterStore) { [string]$Script:Config.VCenterStore } else { 'vcenters' })
    $Script:VCenterStore = $folder
    $file = Join-Path $folder 'vcenters.json'
    if (-not (Test-Path $file)) {
        $blocks = @(if ($Script:Config.ContainsKey('VCenters')) { @($Script:Config.VCenters) } else { @() })
        Save-VcenterList -Blocks $blocks -Author 'migration' -Comment 'Imported from the VCenters block of MIThrandir.config.psd1'
        Write-Journal -Level 'INFO' -Message "vCenter list imported from MIThrandir.config.psd1 ($($blocks.Count) vCenter(s)), now managed from the console" -Data @{ depot = $folder }
    }
    $lu = [System.IO.File]::ReadAllText($file) | ConvertFrom-Json -AsHashtable -Depth 6
    $Script:MetaVCenters = $lu.meta
    $Script:Config.VCenters = @(foreach ($b in @($lu.vcenters)) { if ($b) { $h = @{}; foreach ($k in $b.Keys) { $h[$k] = $b[$k] }; $h } })
}

function Save-VcenterList {
    param([array]$Blocks, [Parameter(Mandatory)][string]$Author, [string]$Comment = '')
    $folder = $Script:VCenterStore
    $history = Join-Path $folder 'history'
    if (-not (Test-Path $history)) { New-Item -ItemType Directory -Path $history -Force | Out-Null }
    $previous = @(Get-ChildItem $history -Filter 'v*.json' -ErrorAction SilentlyContinue | ForEach-Object { [int]($_.BaseName.TrimStart('v')) } | Sort-Object -Descending | Select-Object -First 1)
    $version = if ($previous.Count) { $previous[0] + 1 } else { 1 }
    $own = @(foreach ($b in @($Blocks)) {
        $copy = [ordered]@{}
        foreach ($key in @('Name', 'Zone', 'Server', 'Port', 'CredentialFile', 'CertificateThumbprint', 'Description', 'ModifiedBy', 'ModifiedOn')) { if ($b.ContainsKey($key)) { $copy[$key] = $b[$key] } }
        $copy
    })
    $content = [ordered]@{ meta = [ordered]@{ version = $version; author = $Author; date = (Get-Date).ToString('o'); comment = $Comment }; vcenters = $own }
    $json = ConvertTo-Json -InputObject $content -Depth 6
    $utf8 = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText((Join-Path $history ("v{0:D5}.json" -f $version)), $json, $utf8)
    [System.IO.File]::WriteAllText((Join-Path $folder 'vcenters.json'), $json, $utf8)
    $Script:MetaVCenters = $content.meta
    $Script:Config.VCenters = @(foreach ($b in $own) { $h = @{}; foreach ($k in $b.Keys) { $h[$k] = $b[$k] }; $h })
    return $content.meta
}

function Get-VcentersView {
    <# For the console: configuration and state of each vCenter, never any secret. #>
    $list = @(foreach ($block in @($Script:Config.VCenters)) {
        $e = if ($Script:VcenterConnections.Contains($block.Name)) { $Script:VcenterConnections[$block.Name] } else { $null }
        [ordered]@{
            name = $block.Name; zone = [string]$block['Zone']; server = $block.Server; port = $(if ($block['Port']) { [int]$block.Port } else { 443 })
            thumbprint = [string]$block['CertificateThumbprint']; description = [string]$block['Description']
            account = $(if ($e -and $e.Credential) { $e.Credential.UserName } else { '' })
            credentialPresent = [bool]($e -and $e.Credential)
            connected = [bool]($e -and $e.Connection -and $e.Connection.IsConnected)
            version = $(if ($e -and $e.Connection) { [string]$e.Connection.Version } else { '' })
            error = $(if ($e) { [string]$e.Error } else { 'not loaded yet (restart required)' })
            modifiedBy = [string]$block['ModifiedBy']; modifiedOn = [string]$block['ModifiedOn']
        }
    })
    return [ordered]@{ vcenters = $list; meta = $Script:MetaVCenters; hotApply = [bool]$Script:WithActiveVCenter; depot = $Script:VCenterStore }
}

function Get-ConsoleCertificate {
    param([Parameter(Mandatory)][string]$Server, [int]$Port = 443)
    $c = Get-CertificateThumbprint -HostName $Server -Port $Port
    return [ordered]@{ thumbprint = $c.Thumbprint; subject = $c.Subject; issuer = $c.Issuer; expiresOn = $c.ExpiresOn.ToString('yyyy-MM-dd'); selfSigned = $c.SelfSigned }
}

function Update-VcentersHot {
    <# After a list change: MCP tools are regenerated and the inventory is restarted on the new list. #>
    if (-not $Script:WithActiveVCenter) { return }
    if ($Script:InventoryBackground -or (Get-InventoryConfig).Active) {
        Stop-AutomaticInventory
        if ((Get-InventoryConfig).Active) { Start-AutomaticInventory -AcceptAnyCertificate:$Script:AcceptAnyCertificate }
    }
    $Script:Catalog = Get-ToolCatalog -WithVCenter:$Script:WithActiveVCenter
}

function Set-VCenterConsole {
    <# Adds or modifies a vCenter from the console. The password is DPAPI-encrypted by the MIThrandir process itself
       (hence for its service account) and is never read back by the console. #>
    param([Parameter(Mandatory)][hashtable]$Body, [Parameter(Mandatory)][string]$Author, [bool]$ChannelOn = $false)
    $name = ([string]$Body['name']).Trim()
    if ($name -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$') { throw 'name: 1 to 40 characters, letters, digits, dot, hyphen, underscore' }
    $server = ([string]$Body['server']).Trim()
    if ($server -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]*$|^\[?[0-9A-Fa-f:]+\]?$') { throw 'server: DNS name or IP address expected' }
    $port = if ($Body['port']) { [int]$Body['port'] } else { 443 }
    if ($port -lt 1 -or $port -gt 65535) { throw 'port: between 1 and 65535' }
    $thumbprint = ([string]$Body['thumbprint']).Replace(':', '').Replace(' ', '').ToUpperInvariant()
    if ($thumbprint -notmatch '^[0-9A-F]{40}$') { throw "certificate thumbprint (SHA-1, 40 hexadecimal characters): use the Read certificate button, then check the value" }
    $account = ([string]$Body['account']).Trim()
    $password = [string]$Body['password']

    $existing = @($Script:Config.VCenters | Where-Object { $_.Name -eq $name }) | Select-Object -First 1
    $newItem = [bool]$Body['newItem']
    if ($newItem -and $existing) { throw "a vCenter named $name already exists" }
    if (-not $newItem -and -not $existing) { throw "unknown vCenter: $name" }
    $duplicate = @($Script:Config.VCenters | Where-Object { $_.Name -ne $name -and $_.Server -eq $server -and ([int]$(if ($_['Port']) { $_.Port } else { 443 })) -eq $port })
    if ($duplicate.Count) { throw "this server is already declared under the name $($duplicate[0].Name)" }
    if ($password -and -not $ChannelOn) { throw 'password denied: the console must use HTTPS (or be opened from the MIThrandir machine itself)' }
    if ($newItem -and (-not $account -or -not $password)) { throw 'account and password required for a new vCenter' }
    if ($account -and -not $password -and $existing) {
        $e = $Script:VcenterConnections[$name]
        if (-not ($e -and $e.Credential -and $e.Credential.UserName -eq $account)) { throw 'new account: also enter its password' }
    }

    # Certificate: checked BEFORE anything is saved
    try { $present = Get-CertificateThumbprint -HostName $server -Port $port }
    catch { throw "server $($server):$port unreachable over TLS ($($_.Exception.Message)): nothing saved" }
    if ($present.Thumbprint -ne $thumbprint) { throw "the server presents certificate $($present.Thumbprint), different from the thumbprint entered: nothing saved" }

    $relativeFile = if ($existing) { [string]$existing.CredentialFile } else { Join-Path (Split-Path $Script:VCenterStore -Leaf) ("Credential-{0}.xml" -f $name) }
    $block = @{ Name = $name; Zone = ([string]$Body['zone']).Trim(); Server = $server; Port = $port; CredentialFile = $relativeFile; CertificateThumbprint = $thumbprint; Description = ([string]$Body['description']).Trim(); ModifiedBy = $Author; ModifiedOn = (Get-Date).ToString('o') }

    if ($password) {
        if (-not $account) { throw 'account missing' }
        $path = Resolve-RelativePath $relativeFile
        $folder = Split-Path $path -Parent
        if (-not (Test-Path $folder)) { New-Item -ItemType Directory -Path $folder -Force | Out-Null }
        $credential = [pscredential]::new($account, (ConvertTo-SecureString $password -AsPlainText -Force))
        $credential | Export-Clixml -Path $path -Force
    }

    $blocks = @(@($Script:Config.VCenters | Where-Object { $_.Name -ne $name }) + @($block))
    if ($existing) { $blocks = @(foreach ($b in @($Script:Config.VCenters)) { if ($b.Name -eq $name) { $block } else { $b } }) }
    $what = if ($newItem) { 'added' } else { 'modified' }
    $meta = Save-VcenterList -Blocks $blocks -Author $Author -Comment "vCenter $name $what"
    Write-Journal -Level 'ADMIN' -Message "vCenter $what : $name" -Data @{ author = $Author; vcenter = $name; server = $server; port = $port; zone = $block.Zone; thumbprint = $thumbprint; account = $account; passwordChanged = [bool]$password; version = $meta.version }

    $connected = $false; $errorInfo = ''
    if ($Script:WithActiveVCenter) {
        $entry = if ($Script:VcenterConnections.Contains($name)) { $Script:VcenterConnections[$name] } else { $null }
        $old = if ($entry) { $entry.Connection } else { $null }
        $Script:VcenterConnections[$name] = @{ Name = $name; Config = $block; Credential = $null; Connection = $old; Error = '' }
        try { $Script:VcenterConnections[$name].Credential = Get-VcenterCredential -Block $block }
        catch { $Script:VcenterConnections[$name].Error = $_.Exception.Message }
        if ($Script:VcenterConnections[$name].Credential) {
            $connected = Connect-VcenterInSandbox -Name $name -AcceptAnyCertificate:$Script:AcceptAnyCertificate
        }
        $errorInfo = $Script:VcenterConnections[$name].Error
        Update-VcentersHot
    }
    return [ordered]@{ ok = $true; meta = $meta; connected = $connected; error = $errorInfo; hotApply = [bool]$Script:WithActiveVCenter }
}

function Remove-VCenterConsole {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Author)
    $existing = @($Script:Config.VCenters | Where-Object { $_.Name -eq $Name }) | Select-Object -First 1
    if (-not $existing) { throw "unknown vCenter: $Name" }
    if ($Script:VcenterConnections.Contains($Name)) {
        if ($Script:WithActiveVCenter) { Disconnect-VcenterInSandbox -Name $Name }
        $Script:VcenterConnections.Remove($Name)
    }
    if ($Script:Inventory -and $Script:Inventory.vcenters.ContainsKey($Name)) { $Script:Inventory.vcenters.Remove($Name) }
    $meta = Save-VcenterList -Blocks @($Script:Config.VCenters | Where-Object { $_.Name -ne $Name }) -Author $Author -Comment "vCenter $Name removed"
    # Encrypted credential: deleted only if it is in the store managed by the console
    $path = Resolve-RelativePath ([string]$existing.CredentialFile)
    if ((Test-Path $path) -and ([System.IO.Path]::GetFullPath($path)).StartsWith([System.IO.Path]::GetFullPath($Script:VCenterStore), [StringComparison]::OrdinalIgnoreCase)) { Remove-Item $path -Force }
    Write-Journal -Level 'ADMIN' -Message "vCenter removed: $Name" -Data @{ author = $Author; vcenter = $Name; server = $existing.Server; version = $meta.version }
    Update-VcentersHot
    return [ordered]@{ ok = $true; meta = $meta }
}
