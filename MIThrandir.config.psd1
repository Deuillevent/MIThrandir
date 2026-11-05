@{
    # ----- HTTP listener -----
    Address = 'localhost'        # '+' for all interfaces (netsh reservation required), 'localhost' for a local test
    Port    = 8765

    # ----- MCP client authentication -----
    AllowedIps = @()             # empty = all; otherwise list of source IPs, e.g. @('10.1.2.3')
    Token        = ''              # empty = no token; otherwise each request must carry "Authorization: Bearer <Token>"

    # V4.8.1: a client presenting an unknown Mcp-Session-Id (session opened before a MIThrandir restart)
    # receives HTTP 404 and must redo initialize + tools/list: it thus sees the tools added by a new version.
    # $false = old behavior (any session accepted), to use if a client handles the 404 poorly.
    StrictSessions = $true

    # V4.6: allowed browser origins (Origin header). Empty = no third-party web page (safe by default);
    # declare the exact origin of the llama-server WebUI, wildcards accepted. '*' = everything (avoid in production).
    # A no-browser client (relay, script) sends no Origin and is not affected.
    AllowedOrigins = @()       # e.g. @('http://llm-webui.example.local:8080', 'https://*.example.local')

    # ----- vCenters -----
    # V4.5: the list is managed in the console (Settings, vCenters section) and lives in <VCenterStore>\vcenters.json.
    # This block now serves only as a SEED: it is imported at first startup if vcenters.json does not exist, then ignored.
    # It may stay empty (VCenters = @()): vCenters, accounts and thumbprints are then entered in the console.
    VCenterStore = 'vcenters'
    # One block per vCenter. Name = short identifier used by agents in the Server parameter and by the policy.
    # CredentialFile: one DPAPI-encrypted file per vCenter, created by  MIThrandir-MCP.ps1 -SaveCredential -VCenter <Name>
    # CertificateThumbprint: obtained with  MIThrandir-MCP.ps1 -ShowCertificate ; empty = connection denied unless -AcceptAnyCertificate (accept any certificate)
    VCenters = @()

    # If a listed vCenter is unreachable at startup: $true = start without it (it is marked unavailable), $false = MIThrandir refuses to start
    TolerateUnreachableVCenter = $true

    # PowerCLI modules loaded in the sandbox (offline, already installed). Core is mandatory.
    PowerCliModules = @('VMware.VimAutomation.Core', 'VMware.VimAutomation.Storage', 'VMware.VimAutomation.Vds', 'VMware.VimAutomation.Cis.Core')

    # ----- Automatic inventory (V4.1) -----
    # Cache of VMs, hosts, clusters and datastores, refreshed in a background task (sessions separate from the sandbox).
    # Agents read it through the Get-MIThrandirInventory tool, with the rights of the equivalent cmdlet (Get-VM, Get-VMHost...).
    # CycleTags: tags (Get-TagAssignment, costly) are refreshed one cycle out of N. MaxLimit: maximum objects per response.
    Inventory = @{
        Active              = $true
        IntervalSeconds = 300
        CycleTags          = 6
        Folder            = 'inventory'
        MaxLimit          = 500
    }

    # ----- Identity of the human behind the agent (V4.2) -----
    # /mcp stays anonymous (IP); /mcp-windows/ requires Windows authentication (local relay MIThrandir-Relay.ps1);
    # a trusted relay (e.g. a front end for the llama-server WebUI) forwards an HMAC-signed assertion.
    # 'mandatory' mode: no anonymous call at all. The secret is read from a MACHINE environment variable.
    Identity = @{
        Mode                   = 'mixed'
        DefaultDomain       = ''
        AssertionDelaySeconds = 120
        ResolveGroups        = $true
        Relay = @(
            @{ Name = 'trusted-relay'; IP = @('127.0.0.1', '::1'); VariableSecret = 'MITHRANDIR_SECRET_RELAY' }
        )
    }

    # ----- Sentinel alerts (V4.2) -----
    # Webhook: Format 'teams' (card), 'mattermost' (also Slack) or 'json'. Smtp: internal relay, service account authentication.
    Alerts = @{
        Webhook = @{ Active = $false; Url = ''; Format = 'teams' }
        Smtp    = @{ Active = $false; Server = 'smtp.example.local'; Port = 25; Ssl = $false; From = 'mithrandir@example.local'; To = @('ops@example.local') }
    }

    # ----- Policies -----
    # Versioned store: <PolicyStore>\active.json + history\vNNNNN.json. At first startup, Policy.psd1 is migrated to v1.
    PolicyStore  = 'policies'
    PolicyFile = 'Policy.psd1'

    # ----- Administration console -----
    # Second port, integrated Windows authentication (Negotiate). Access: members of one of the AllowedGroups or one of the AllowedUsers;
    # if both lists are empty, only the machine's local administrators get in.
    # Https = $true assumes a certificate bound to the port: netsh http add sslcert ipport=0.0.0.0:8766 certhash=<thumbprint> appid={<guid>}
    Console = @{
        Active                 = $true
        Address               = 'localhost'      # '+' all interfaces; 'localhost' to allow only the machine itself
        Port                  = 8766
        Https                 = $false
        AllowedGroups      = @()              # e.g. @('DOMAIN\GG-MIThrandir-Admins')
        AllowedUsers = @()     # e.g. @('DOMAIN\jdoe')
        # MCP clients classified as "chat" (bubble icon) rather than "agentic" (robot icon), based on the name announced at initialization
        ChatClientPatterns = @('*webui*', '*llama*', '*chat*', '*open-webui*', '*librechat*')
    }

    # ----- Log export to security -----
    # Each event is also sent, asynchronously, to Splunk HEC and/or a syslog collector (SIEM).
    # If the target is unavailable, events are kept in journal\spool and replayed.
    Export = @{
        Splunk = @{
            Active             = $false
            Url               = 'https://splunk.example.local:8088/services/collector/event'
            Token             = ''               # HEC token
            Index             = 'infra'
            SourceType        = 'mithrandir:json'
            IgnoreCertificate = $false
        }
        Syslog = @{
            Active     = $false
            Host      = 'siem.example.local'
            Port      = 514
            Protocol = 'udp'                    # 'udp' or 'tcp' (RFC 6587, octet-counting)
            Format    = 'cef'                    # 'cef' (ArcSight/Sentinel/QRadar) or 'json' (raw line)
        }
        # V4.6: OpenTelemetry export (OTLP/HTTP JSON logs) to an OpenTelemetry collector (/v1/logs endpoint).
        # Same asynchronous queue and same spool as Splunk/syslog. All three targets can be active together.
        Otlp = @{
            Active             = $false
            Endpoint          = 'http://otel-collector.example.local:4318'   # OTLP/HTTP base; MIThrandir appends /v1/logs
            Headers           = @{}              # e.g. @{ 'Authorization' = 'Bearer <token>' } for an OTLP gateway
            IgnoreCertificate = $false
        }
    }

    # ----- OpenMetrics metrics (V4.6) -----
    # GET /metrics endpoint on the MCP port, in OpenMetrics format: scraped by Prometheus or by the
    # prometheus receiver of an OpenTelemetry collector. Read-only, no token. Empty AllowedIps = same IPs as the gateway
    # (and always localhost). Set Active = $false to disable the endpoint.
    Metrics = @{
        Active        = $true
        AllowedIps = @()                       # e.g. @('10.1.2.10'): IP of the collector or of Prometheus
    }
}
