<#
.SYNOPSIS
    Identity of the human behind the agent (MIThrandir V4.2).

.DESCRIPTION
    Three ways for an MCP call to reach MIThrandir:
      1. /mcp            anonymous: only the IP address is known (historical behavior);
      2. /mcp-windows/   integrated Windows authentication (Kerberos / NTLM): the identity is the person's Windows
                         session. This is the path used by the local relay MIThrandir-Relay.ps1 (command-line
                         agents on a Windows workstation);
      3. /mcp + signed assertion from a TRUSTED RELAY (e.g. a front end for the llama-server web interface):
         headers X-MIThrandir-Identity (JSON payload in base64url) and X-MIThrandir-Signature (HMAC-SHA256 with a shared
         secret), accepted only from the relay's declared address and within AssertionDelaySeconds (assertion
         validity window, in seconds).
    The account and its AD groups feed the rules (Subjects.Accounts, Subjects.Groups), the log (user field,
    suser in CEF), the agent cards and the sentinel (the score follows the person when known).

    MIThrandir.config.psd1 :
        Identity = @{
            Mode = 'mixed'                     # 'mixed': anonymous accepted; 'mandatory': every call must be identified
            DefaultDomain = 'AD'            # prefix for accounts without a domain
            AssertionDelaySeconds = 120
            ResolveGroups = $true            # the account's AD groups (cached 10 min)
            Relay = @( @{ Name = 'trusted-relay'; IP = @('10.1.2.3'); VariableSecret = 'MITHRANDIR_SECRET_RELAY' } )
        }
#>

$Script:CurrentIdentity = @{ Account = ''; Groups = @(); Source = 'ip'; Name = '' }
$Script:GroupsCache = @{}

function Get-IdentityConfig {
    $cfg = @{ Mode = 'mixed'; DefaultDomain = ''; AssertionDelaySeconds = 120; ResolveGroups = $true; Relay = @() }
    if ($Script:Config.ContainsKey('Identity') -and $Script:Config.Identity -is [hashtable]) { foreach ($key in @($Script:Config.Identity.Keys)) { $cfg[$key] = $Script:Config.Identity[$key] } }
    $cfg.Relay = @($cfg.Relay | Where-Object { $_ })
    return $cfg
}

function Reset-CurrentIdentity { $Script:CurrentIdentity = @{ Account = ''; Groups = @(); Source = 'ip'; Name = '' } }

function Get-WindowsGroups {
    <# Groups of an authenticated Windows identity (Kerberos/NTLM token): translates SIDs to names. #>
    param([System.Security.Principal.WindowsIdentity]$Identity)
    $key = "win|$($Identity.Name)"
    if ($Script:GroupsCache.ContainsKey($key) -and $Script:GroupsCache[$key].Expire -gt (Get-Date)) { return $Script:GroupsCache[$key].Groups }
    $names = @(foreach ($sid in $Identity.Groups) { try { $sid.Translate([System.Security.Principal.NTAccount]).Value } catch { } })
    $Script:GroupsCache[$key] = @{ Groups = $names; Expire = (Get-Date).AddMinutes(10) }
    return $names
}

function Get-AccountGroups {
    <# AD groups of an account forwarded by a relay (no Windows token): directory lookup, cached. #>
    param([string]$Account)
    $key = "ad|$Account"
    if ($Script:GroupsCache.ContainsKey($key) -and $Script:GroupsCache[$key].Expire -gt (Get-Date)) { return $Script:GroupsCache[$key].Groups }
    $names = @()
    try {
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement -ErrorAction Stop
        $domain, $login = if ($Account -match '^([^\\]+)\\(.+)$') { $Matches[1], $Matches[2] } else { $null, $Account }
        $context = if ($domain) { [System.DirectoryServices.AccountManagement.PrincipalContext]::new([System.DirectoryServices.AccountManagement.ContextType]::Domain, $domain) } else { [System.DirectoryServices.AccountManagement.PrincipalContext]::new([System.DirectoryServices.AccountManagement.ContextType]::Domain) }
        $user = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($context, $login)
        if ($user) { $names = @($user.GetAuthorizationGroups() | ForEach-Object { if ($domain) { "$domain\$($_.SamAccountName)" } else { $_.SamAccountName } }) }
    }
    catch { }
    $Script:GroupsCache[$key] = @{ Groups = $names; Expire = (Get-Date).AddMinutes(10) }
    return $names
}

function Resolve-RequestIdentity {
    <# Returns @{ Ok; Reason; Identity } and sets $Script:CurrentIdentity for the duration of the request. #>
    param([System.Net.HttpListenerContext]$Context, [string]$Path)
    Reset-CurrentIdentity
    $cfg = Get-IdentityConfig
    $request = $Context.Request
    $ip = (Get-RequestIp -Request $request)

    if ($Path -eq '/mcp-windows') {
        $user = $Context.User
        if ($null -eq $user -or -not $user.Identity.IsAuthenticated) { return @{ Ok = $false; Reason = 'Windows authentication missing on /mcp-windows' } }
        $groups = @()
        if ($cfg.ResolveGroups -and $user.Identity -is [System.Security.Principal.WindowsIdentity]) { $groups = @(Get-WindowsGroups -Identity $user.Identity) }
        $Script:CurrentIdentity = @{ Account = $user.Identity.Name; Groups = $groups; Source = 'windows'; Name = $user.Identity.Name }
        return @{ Ok = $true; Identity = $Script:CurrentIdentity }
    }

    $token = $request.Headers['X-MIThrandir-Identity']
    $signature = $request.Headers['X-MIThrandir-Signature']
    if ($token -or $signature) {
        $relay = @($cfg.Relay | Where-Object { $ip -in @($_.IP) }) | Select-Object -First 1
        if (-not $relay) { return @{ Ok = $false; Reason = "identity assertion presented by $ip, which is not a trusted relay" } }
        $secret = [Environment]::GetEnvironmentVariable([string]$relay.VariableSecret, 'Machine')
        if (-not $secret) { $secret = [Environment]::GetEnvironmentVariable([string]$relay.VariableSecret) }
        if (-not $secret) { return @{ Ok = $false; Reason = "secret of relay $($relay.Name) missing (variable $($relay.VariableSecret))" } }
        $hmac = [System.Security.Cryptography.HMACSHA256]::new([System.Text.Encoding]::UTF8.GetBytes($secret.Trim()))
        try { $expected = -join ($hmac.ComputeHash([System.Text.Encoding]::ASCII.GetBytes([string]$token)) | ForEach-Object { $_.ToString('x2') }) } finally { $hmac.Dispose() }
        if (-not [System.Security.Cryptography.CryptographicOperations]::FixedTimeEquals([System.Text.Encoding]::ASCII.GetBytes($expected), [System.Text.Encoding]::ASCII.GetBytes([string]$signature).Clone())) {
            return @{ Ok = $false; Reason = "invalid identity signature (relay $($relay.Name))" }
        }
        try {
            $b64 = ([string]$token).Replace('-', '+').Replace('_', '/'); $b64 += '=' * ((4 - $b64.Length % 4) % 4)
            $charge = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64)) | ConvertFrom-Json -AsHashtable
        }
        catch { return @{ Ok = $false; Reason = "unreadable identity assertion (relay $($relay.Name))" } }
        $age = [math]::Abs([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - [long]$charge.ts)
        if ($age -gt [int]$cfg.AssertionDelaySeconds) { return @{ Ok = $false; Reason = "expired identity assertion ($age s, relay $($relay.Name))" } }
        $account = [string]$charge.account
        if (-not $account) { return @{ Ok = $false; Reason = "identity assertion without account (relay $($relay.Name))" } }
        if ($account -notmatch '[\\@]' -and $cfg.DefaultDomain) { $account = "$($cfg.DefaultDomain)\$account" }
        $groups = if ($cfg.ResolveGroups) { @(Get-AccountGroups -Account $account) } else { @() }
        $Script:CurrentIdentity = @{ Account = $account; Groups = $groups; Source = "relay:$($relay.Name)"; Name = [string]$charge.name; ClientHost = [string]$charge.ip }
        return @{ Ok = $true; Identity = $Script:CurrentIdentity }
    }

    if ($cfg.Mode -eq 'mandatory') { return @{ Ok = $false; Reason = "anonymous call denied (Identity.Mode = mandatory): go through /mcp-windows/ or a trusted relay" } }
    return @{ Ok = $true; Identity = $Script:CurrentIdentity }
}

function New-MIThrandirSubject {
    <# Rule-evaluation subject: caller IP, plus the account and groups when known. #>
    param([string]$IP)
    return @{ IP = $IP; Account = [string]$Script:CurrentIdentity.Account; Groups = @($Script:CurrentIdentity.Groups) }
}

function Get-AgentKey {
    <# Tracking key (sentinel, suspension): the person when known, otherwise the IP address. #>
    param([string]$IP)
    if ($Script:CurrentIdentity.Account) { return [string]$Script:CurrentIdentity.Account }
    return $IP
}
