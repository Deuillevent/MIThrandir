@{
    # MIThrandir initial policy: evaluated BEFORE each execution. Data file, reloaded at startup.

    # ----- What agents may execute -----
    # Allowed PowerCLI cmdlets (wildcard patterns). Only VMware.* modules are considered.
    AllowedCmdlets = @('Get-*')
    # Cmdlets denied even if they match a pattern above
    ExcludedCmdlets    = @('Get-EsxCli', 'Get-View', 'Get-VICredentialStoreItem', 'Get-VMHostAccount', 'Get-VMGuestNetworkInterface', 'Get-ErrorReport', 'Get-VIEvent', 'Get-Log', 'Get-LogType')
    # PowerShell formatting cmdlets allowed in a pipeline (with script blocks limited to simple expressions)
    Utilities       = @('Where-Object', 'Select-Object', 'Sort-Object', 'Group-Object', 'Measure-Object', 'Select-Object')
    # Parameters denied on all cmdlets
    ExcludedParameters  = @('Id', 'RelatedObject', 'Tag', 'NoRecursion')
    # Parameters denied per cmdlet
    ExcludedParametersPerCmdlet = @{
        'Get-VM' = @('Datastore')   # example: remove what is not wanted, leave empty to allow everything
    }
    # Properties never returned, whatever the object (exact names, case-insensitive)
    ExcludedProperties = @('Notes', 'Description', 'CustomFields', 'ExtensionData', 'Client', 'Uid', 'Password')

    # Cmdlets additionally exposed as typed MCP tools (schema generated from the installed PowerCLI). Invoke-PowerCLI remains available for everything else.
    TypedTools = @('Get-VM', 'Get-VMHost', 'Get-Cluster', 'Get-Datastore', 'Get-Snapshot', 'Get-Folder', 'Get-ResourcePool', 'Get-Datacenter')

    # ----- Execution limits -----
    MaxBatchSize      = 50       # maximum objects per response
    DefaultBatchSize   = 25
    MaxOutputSize   = 60000    # maximum characters returned to the model
    MaxDelaySeconds  = 120      # a PowerCLI line that exceeds this is interrupted

    # ----- Scope and quotas -----
    TimeRange        = @{ Start = '00:00'; End = '23:59' }   
    CallQuotaPerHour = 120

    # ----- Per-agent rights (source IP), 'default' for unlisted IPs -----
    # Tools: MCP tool names (Invoke-PowerCLI, Get-VIServer, Get-MIThrandirTime, and the typed tools); '*' = all
    # Cmdlets: subset of AllowedCmdlets for this agent; '*' = everything the global policy allows
    # VCenters: short names from MIThrandir.config.psd1; '*' = all. The others are invisible to the agent.
    Agents = @{
        'default'   = @{ Tools = @('*'); Cmdlets = @('*'); VCenters = @('*') }
        # '10.1.2.3' = @{ Tools = @('Invoke-PowerCLI', 'Get-VIServer'); Cmdlets = @('Get-VM', 'Get-Snapshot', 'Get-Datastore'); VCenters = @('vc-test') }
    }
}
