# MIThrandir: detailed history

Detailed notes of earlier versions, kept from the internal history. `Vx.y` corresponds to release `0.xy`
(V4.8 is 0.48). See also [CHANGELOG.md](../CHANGELOG.md).

## What's new in V4.8 (2 November 2026)
- New dark theme (neutral blue-grey); light mode unchanged.
- Console, "Rules" page: universal search (which rules apply to an object: agent, account, vCenter, scope, group, cmdlet, flag) + compound target tester ("Test a compound target").
- Console, "Rules" page: "From agent activity to a rule": from the journal to a group / a draft Allow rule.
- Agent-side discovery: MCP tools Get-MIThrandirCapabilities (engine limits, including the number of objects returned: 25 by default, 50 at most) and Get-MIThrandirMyRights (the agent's RSoP). Added to the diagnostic-mithrandir group, logged at INFO level.
- Interface: all console icons replaced by the single image icon/mithrandir-icon.png (file reference).

Note: "V4.8" is the label of this delivery; the version number displayed in the console comes from the policy active at runtime.

---


## What's new in V4.6 (31 October 2026): hardening after a review of the team's scripts

Review of the team's real PowerCLI scripts (the kinds of requests made to agents) and of the code. Get-View is now
ALLOWED (too useful to exclude), but bounded; six read bypasses were closed; load limits were added. Every point
below has a test in `_tests_v46.ps1`.

### Get-View allowed but bounded (`Global.Views`, `Validation-AST.ps1`, `Sandbox.ps1`)
- Get-View leaves `ExcludedCmdlets` and joins a `read-views` group (included in `read-poc` by default).
  Read-only operation remains guaranteed (no method calls: AST + ConstrainedLanguage; read-only vCenter role).
- `-Property` is MANDATORY (a full view weighs hundreds of KB per VM), at most 40 paths (`Views.MaxProperties`).
- Object types are allow-listed (`Views.Types`) for `-ViewType`, `-Id` (MoRef) and `-SearchRoot`: VMs, hosts, clusters,
  datastores, folders, datacenters, pools, networks. SessionManager, OptionManager, AuthorizationManager... are refused.
- Forbidden property paths (`Views.ForbiddenPaths`), in `-Property` AND in `-Filter`, and also stripped from the
  returned views (defense in depth): `Config.Annotation` (= Notes), `Config.ExtraConfig` (guestinfo.*),
  `Config.VAppConfig`, custom attributes (`CustomValue`, `Value`, `AvailableField`), `Config.Option`.
  Requesting an ancestor (`-Property Config`) is refused; `-Filter` accepts only constant keys and values.
- Returned views are FLATTENED (`Config.Tools.ToolsVersion = "12352"`) and MoRefs are rendered as `Type-value`.
  The scope filter also recognizes views (by `Client.ServiceUrl` and `MoRef`): Get-View is filtered by tag
  exactly like Get-VM.

### Read bypasses closed (`Validation-AST.ps1`)
Masked properties (`ExcludedProperties`: Notes, ExtensionData...) no longer leak through these paths:
- wildcards in property-name position are refused (`Select-Object -ExpandProperty N*tes`, `-Property Ext*`);
- the value of a calculated property is checked (`Select-Object @{N='n';E='Notes'}`);
- the `-Property` of a `Where-Object` is checked (oracle `Where-Object -Property N*tes -Like 'pwd*'`);
- access to `$_.PSObject` is refused (`$_.PSObject.Properties['Notes'].Value`);
- `Get-Annotation`, `Get-CustomAttribute` and `Get-AdvancedSetting` (on a VM: ExtraConfig / guestinfo.*) are excluded.
Reminder: the value in a comparison (`Where-Object Name -Like 'SRV-*'`) remains allowed; only the property NAME is bounded.

### Load limits
- Mandatory targeting (`Global.MandatoryTargeting`) of costly cmdlets (Get-Stat, Get-TagAssignment, Get-HardDisk,
  Get-NetworkAdapter, Get-ScsiLun): such a cmdlet at the head of a pipeline must carry `-Name/-Id/-Entity/-VM/-Location...`
  that actually targets something (not just `*`), or receive a PowerCLI pipeline upstream (`Get-VM -Name ... | Get-Stat`).
- Sandbox time budget per agent (`Global.SandboxSecondsPerHour`, 900 s by default, sliding over 1 h): bounds a single agent
  regardless of the number of calls. 0 = unlimited. Tracked by the identity key (the person if known, otherwise the IP).
- `Global.MaxOutputSize` lowered to 20,000 characters by default (two responses fit in a 32k context and
  could overflow the model). Existing policies keep their value.

### Request origin (anti-CSRF, `MIThrandir.config.psd1`, `MIThrandir-MCP.ps1`, `Console.ps1`)
- New setting `AllowedOrigins`: the `Origin` header of a browser is accepted only if it is listed there (wildcards
  allowed). Empty = no third-party web page (safe by default); declare the exact origin of the llama-server WebUI.
  No-browser clients (relays, scripts) do not send an Origin and are not affected.
- The console (Windows authentication) refuses a POST/DELETE whose `Origin` is not its own origin.

### OpenTelemetry observability (`Journal.ps1`, `MIThrandir.config.psd1`, `MIThrandir-MCP.ps1`)
- **OTLP logs**: new `Export.Otlp` target alongside Splunk and syslog. Every log event is also sent over
  OTLP/HTTP (JSON) to an OpenTelemetry collector (`<Endpoint>/v1/logs`), through the same asynchronous queue and the same spool
  (replayed if the collector is unreachable). OTel severity is mapped (DENIED = WARN, ERROR = ERROR, ALERT = FATAL),
  with attributes `mithrandir.agent`, `enduser.id`, `mithrandir.reason`, `mithrandir.line`, `mithrandir.durationMs`... Free-form headers
  (`Headers`) for an authenticated gateway. The three targets (Splunk, syslog, OTLP) can be combined.
- **OpenMetrics metrics**: `GET /metrics` endpoint on the MCP port (OpenMetrics format, read-only, no token),
  scraped by Prometheus or by the prometheus receiver of an OpenTelemetry collector. Counters (`mithrandir_calls_total`,
  `mithrandir_denial_total`, `mithrandir_errors_total`, `mithrandir_export_*`...) and gauges (`mithrandir_agents`,
  `mithrandir_gateway_suspended`, `mithrandir_inventory_age_seconds{vcenter}`, `mithrandir_inventory_vms{vcenter}`,
  `mithrandir_sentinel_suspicion{agent}`, `mithrandir_sentinel_protection`). Setting `Metrics` (Active, AllowedIps;
  localhost always allowed). No dependency added: everything is pure PowerShell, compatible with offline installation.

### Write mode for testing blocks (`Global.AllowWrite`, `Policy.ps1`)
- By default MIThrandir stays **read-only**: the allow-list accepts only `Get-*` patterns (refused at validation otherwise).
- `Global.AllowWrite = $true` (console: "Global settings" > "Commands" > "Allowed commands (allow list)" > *Allow writing*) lifts this
  restriction: the allow-list can then contain `*` (all PowerCLI cmdlets) or write patterns
  (`Set-VM*`, `Start-*`...). Its purpose is to **verify that the rules do block** writes (a write cmdlet not
  covered by an Allow rule is refused; a Deny rule blocks it). Use only for testing, ideally with a
  **read-only vCenter service account**: even if a command passes all of MIThrandir's walls, vCenter
  rejects it. In write mode, `-WhatIf` and `-Confirm` are allowed (dry runs, non-interactive execution).
- Permanent safeguards, whatever the allow-list (even `*`): connection / session cmdlets
  (`Connect-VIServer`, `Disconnect-VIServer`, `Connect-CisServer`, `Disconnect-CisServer`, `Set-PowerCLIConfiguration`)
  are **always refused** and remain invisible in the sandbox (MIThrandir manages sessions itself).

### Viewing the inventory from the console (`Console.html`, "Inventory" page)
- New **Inventory** page (under "Supervision"): an administrator sees **what agents read** through the
  `Get-MIThrandirInventory` tool (same cache, same function). Filters identical to the MCP tool: Type (VM, Hosts, Clusters,
  Datastores), Name (wildcards), Cluster, Folder, Tag, State, and "Group by" (counts). Freshness per vCenter, refresh button
  (*Refresh the inventory cache*). Table with all exposed properties and tags, capped as for agents.
- Reuses the existing route `GET /api/inventory/objects` (no new right). Excluded properties
  (`ExcludedProperties`) do not appear there, exactly as for an agent.

### Backward compatibility
- The new settings (`Views`, `MandatoryTargeting`, `SandboxSecondsPerHour`, `AllowedParametersPerCmdlet`, `AllowWrite`) receive
  default values when an earlier policy is read. Get-View stays excluded as long as it appears in
  `ExcludedCmdlets` of an existing policy: remove it (console, "Global settings") to enable the read-views group.

### Recommended next (not coded: architecture changes to validate on the test bench)
- Move the console out of the MCP loop (listener in its own runspace) so that *Suspend* remains available during
  a long call. Today the loop handles one request at a time.
- Truly forced stop beyond `MaxDelaySeconds` (the current stop waits for the end of the ongoing SOAP call):
  via a sandbox pool outside the main thread.
- Sandbox pool, pagination with an offset on `Get-MIThrandirInventory` rather than on Invoke-PowerCLI.

## What's new in V4.5 (31 October 2026)

### vCenters managed from the console ("Global settings" page, "vCenters" tab)
- Add, modify, remove a vCenter without touching a file: short name, zone, server and port, description.
- **Certificate**: button *Read the certificate* (subject, issuer, expiry, self-signed). The thumbprint is verified
  before any save; if the server presents a different certificate, nothing is saved.
- **Account and password** entered in the console, DPAPI-encrypted by the MIThrandir process itself, hence for its
  service account (no more `-SaveCredential` to run under a gMSA). The password is never redisplayed,
  returned by the API or logged. It is **refused** if the console is on HTTP from another machine: HTTPS required,
  except from the MIThrandir machine itself.
- **Hot**: connection (or closing) of the session in the sandbox, inventory restart, MCP tools
  regenerated. Without `-WithVCenter`, the change is saved and applied at the next start.
- Versioned list (`vcenters\history\`), each action logged as ADMIN (author, server, thumbprint, account,
  `passwordChanged`). Rights: any console administrator.
- The short name no longer changes after creation (it is used by agents and in rules). Removing a vCenter
  deletes its encrypted credential if it is in `vcenters\`; the rules and scopes that mention it remain.
- Migration: on first start, the `VCenters` block of `MIThrandir.config.psd1` is imported into `vcenters\vcenters.json`
  (existing credentials kept), then ignored. New setting `VCenterStore` (default `vcenters`).
- A missing or unreadable credential no longer blocks startup: the vCenter is marked in error and is fixed
  in the console. MIThrandir also starts with an empty list.
- Routes: `GET /api/vcenters/config`, `POST /api/vcenters/certificate`, `POST /api/vcenters/save`,
  `POST /api/vcenters/remove`. Tests: `_tests_vcenters.ps1` (15/15 on the test bench).

### Icon
- Black halo around the staff light removed (console logo, tab icon, `icon\`).

## What's new in V4.4 (31 October 2026)

### Scopes inside vCenters (`Scope.ps1`)
A scope can now restrict the agent to part of a vCenter, and this filtering is **enforced** (it was only recorded until now).
- Criteria: **Tags** (`Category/Value`, e.g. `App/APP-A`, `Env/Production`, `Team/ONE`), **Clusters**, **Folders** (a folder includes its subfolders), **VM names**.
  Wildcards `*` and `?`; a value starting with `^` is a regular expression.
- Combination: AND between criterion types, OR between values of the same type.
  For tags: OR within a category, AND between categories. `App/APP-A` + `Env/Production` = application APP-A in production only.
- With no criterion, the scope opens entire vCenters (behavior unchanged).
- Enforcement:
  - MIThrandir inserts `Select-MIThrandirScope` after each PowerCLI cmdlet of the line. A VM outside the scope does not exist for the agent: `Get-VM -Name` does not find it and `Measure-Object` does not count it.
  - Child objects (disks, snapshots, network adapters, statistics) are filtered by their parent VM.
  - A nested PowerCLI cmdlet (`Get-HardDisk -VM (Get-VM ...)`) is refused when the scope is restricted.
  - Hosts, clusters, datastores and networks are masked, unless the scope has *Keep hosts, clusters and datastores visible* checked (`InfraVisible`).
  - Objects without a vSphere identifier (events, for example) are discarded.
  - The `Get-MIThrandirInventory` tool applies the same filter.
- The retained VMs are computed from the inventory cache. A VM created since the last cycle appears only at the next cycle. If a vCenter's cache is not loaded, no VM of that vCenter is visible (deny by default).
- Several rules that allow the same command: union of their scopes. A whole-vCenter scope wins.
- The response to the agent includes `scope.filter`, `scope.visibleVms` and the warning, if any. The CALL log entry carries `filterScope` and `vmScope`.

### Console, "Scopes" page
- Inventory explorer with the number of VMs for each entry:
  - tags by category (App, Env, Team first);
  - clusters by vCenter and datacenter;
  - folder tree.
- Search within lists and manual entry of patterns.
- Live preview: number of VMs visible per vCenter and example names, before saving.
- New routes: `GET /api/inventory/tree`, `POST /api/scopes/preview`; `POST /api/scopes` accepts `infraVisible`.
- New MIThrandir icon (menu logo and tab icon); files `mithrandir-icon.png` and `mithrandir.ico` provided separately.

### Known limitation
- The simulator was not modified: it does not yet show per-VM filtering.

## What's new in V4.3 (31 October 2026)

### Create a group and a rule from existing scripts (`Scripts.ps1`)
- Console > "Command groups" > "From scripts": drop one or more .ps1 files (100 files, 5 MB) or
  paste a script. MIThrandir ANALYZES the PowerShell syntax tree (never executes) and lists each command:
  allowed (proposed), globally excluded, write (Set-, Remove-...), no-PowerCLI (Export-Csv, Write-Host...),
  unknown (module missing), connection (managed by MIThrandir), utility. Aliases resolved (gci, select, where, ?),
  functions defined in the scripts ignored, dynamic calls (& $x, Invoke-Expression) flagged.
- For each cmdlet: number of calls, scripts and lines, parameters used (in red if excluded).
- Literal values of -Server are matched against the declared vCenters and pre-check the scope.
- One-click creation: the command group, and optionally an Allow rule as a DRAFT (inactive, flag
  "To review") for the agents or accounts specified. API: `POST /api/scripts/analyze { scripts: [{ name, content }] }`.

## What's new in V4.2 (31 October 2026)

### Sentinel: agent drift detection (`Sentinel.ps1`)
- SUSPICION score per agent (0 to 100): each refusal adds a weight depending on its nature
  (bypass 15, write 12, sensitive data 10, probing 8, out of scope 6, rule refusal 4, quota 3,
  burst 10, syntax 1, already restricted 5), x1.5 from 4 refusals in 10 min, x2 from 8. Half-life 30 min: isolated
  errors fade away. GOOD USE index (0 to 100) that rises with successful calls.
- Levels: watch (25) = alert + warning added to the agent's responses; restricted (50) = no more direct
  access to vCenters (diagnostics and cached inventory only); quarantine (80) = automatic suspension,
  notification, PROTECTION MODE (red banner in the console). 2 quarantines within 30 min = global protection
  (all agents restricted). Persistent state (`journal\sentinel.json`).
- Communication: ALERT log level (CEF severity 9, hence SIEM), console ("Sentinel" page, banner, badge),
  Teams / Mattermost / JSON webhook and SMTP email (`Alerts` section of the configuration).
- Thresholds, weights and reactions editable in the console (versioned in the policy, `Global.Sentinel`).
  Acknowledgment by an administrator (score reset to zero), manual quarantine, test alert button.
- Test bench measurement: 10 chained bypass attempts => watch, restriction and then quarantine within 1 s.

### Identity of the human behind the agent (`Identity.ps1`, `MIThrandir-Relay.ps1`)
- `/mcp` remains anonymous (IP address). New `/mcp-windows/` (same port) with integrated Windows authentication.
- `MIThrandir-Relay.ps1`: stdio MCP server launched by the agent on the workstation, under the person's Windows session;
  it relays to `/mcp-windows/` using Kerberos/NTLM. No secret stored. MCP client registration (stdio server):
  `pwsh -NoProfile -ExecutionPolicy Bypass -File C:\Tools\MIThrandir\MIThrandir-Relay.ps1 -Url http://mithrandir-01.example.local:8765/mcp-windows/`
- Trusted relay (e.g. a front end for the llama-server WebUI): headers `X-MIThrandir-Identity` (base64url JSON
  payload) and `X-MIThrandir-Signature` (HMAC-SHA256, secret shared through a machine environment variable), accepted
  only from the relay's declared IP and for 120 s. A forged signature counts as a bypass.
- The account and its AD groups (cached 10 min) feed the rules (`Subjects.Accounts`, `Subjects.Groups`), the log
  (field `user`, `suser` in CEF), the agent cards and the sentinel (the score follows the person).
- `Identity.Mode = 'mandatory'` refuses any anonymous call. A netsh reservation must also be planned for
  `http://+:8765/mcp-windows/` in production.

### Rule validity windows (reminder, since V4)
- Start and end dates, days of the week, time range (including across midnight), single use.

## What's new in V4.1 (31 October 2026)

### New console
- Complete redesign of `Console.html` (still a single file, no external resource, works offline).
- Light / dark mode (button at the top right, choice remembered in the browser), 8-bit logo, monochrome icons.
- Dashboard: indicators, "Live stream" diagram agents > MIThrandir walls > vCenters, 60-minute load, most-used rules, latest commands and latest refusals.
- Rules: filters by state, flags (Prioritized, Critical, Temporary, Single use, To review), pinned priority rules, detail panel with actions.
- Command groups: checkboxes on the cmdlets actually installed, grouped by category or by risk; wildcard patterns preserved; globally excluded cmdlets are locked.
- Scopes: vCenter map by zone (optional `Zone` key in `MIThrandir.config.psd1`), inclusion by click, coverage (hosts, VMs) from the inventory.
- Agents: one card per agent (robot = agentic, bubble = chat), hourly quota, 24 h activity, accessible vCenters, rules.
- Global settings: tiles by category; excluded cmdlets as checkboxes sorted by type.
- Log: filters All / Agentic / Discussion / Admin / System events and by level, 24 h histogram, expandable detail.
- Simulator, SIEM export, Versions: functions unchanged (the simulator also accepts Get-MIThrandirInventory).
- The agentic / chat type comes from the MCP client name announced at initialization (`Console.ChatClientPatterns`). Limitation: only one client per IP address (the last one initialized).

### Rule flags
- Optional `Flags` field in each rule: `prioritized`, `critical`, `temporary`, `single-use`, `to-review`. Validated by `Test-PolicyConsistency`, route `POST /api/rules/flags { id, flags }` (new policy version).
- Display and sorting only: evaluation does not change (a Deny always wins).

### Automatic inventory (cache)
- `Inventory-Background.ps1` runs in a separate pwsh PROCESS, started and stopped by MIThrandir; it rereads each vCenter every `Inventory.IntervalSeconds` (300 by default) through `Get-View -Property` (VMs, hosts, clusters, datastores), and tags once every `CycleTags` cycles.
- One JSON snapshot per vCenter in `inventory\`, reloaded at restart. Credentials: the same DPAPI files (same account, same machine).
- MCP tool `Get-MIThrandirInventory`: Type (VM, VMHost, Cluster, Datastore), filters Name, Cluster, Folder, Tag, PowerState, Property, GroupBy, Limit (max `MaxLimit`). The response gives the age of the data per vCenter.
- Rights: exactly those of the equivalent cmdlet (Get-VM, Get-VMHost, Get-Cluster, Get-Datastore; + Get-TagAssignment if filtering by tag), same scopes, quotas and log. No rule to modify. Real PowerCLI cmdlets are never redirected to the cache.
- Console: freshness on the dashboard and the scopes, button "Refresh now" ("Global settings" > "Inventory"). API: `GET /api/inventory`, `POST /api/inventory/refresh`, `GET /api/inventory/objects`.
- Control from the console ("Global settings" > "Inventory" > "Automatic inventory"): enable / disable, period (1 min to 6 h), tag cycle, objects per response, applied hot (background process restarted, MCP tool removed if disabled), logged as ADMIN. These settings are written to `inventory\settings-console.json` and take precedence over `MIThrandir.config.psd1`; delete this file to go back to the psd1. API: `POST /api/inventory/settings { active, intervalSeconds, cycleTags, maxLimit }`.
- Test bench measurement: 1,080 VMs and 66 hosts reread in 1.4 s (vcsim).

### Fix
- PowerCLI resynchronizes `$DefaultVIServer(s)` (AllScope variables) at the start of its cmdlets; in ConstrainedLanguage this write fails ("Specified method is not supported"). MIThrandir detects this case, resynchronizes in FullLanguage with a fixed command (no agent input), then replays the line (`Sandbox.ps1`, `Sync-VariablesPowerCLI`).

## What's new in V4: rules engine

The policy is no longer a flat document but consists of:

- **Global settings**: cmdlet allow-list (the sandbox is locked to it), utilities, excluded parameters and
  properties, typed tools, limits, default quota. What is not allowed here does not exist for anyone.
- Reusable **command groups** (read-inventory, read-storage, read-network, read-performance,
  read-configuration-host, diagnostic-mithrandir, all-read), editable in the console.
- Named **scopes** (vCenters today; tags, clusters, folders, VM patterns recorded for V4.1);
  an implicit scope `vc:<name>` exists for each declared vCenter.
- **Rules**: who (agent IPs, prepared AD accounts and groups), what (groups, cmdlets, tools), where (scopes),
  when (start and end dates, days, time range, maximum usage), how much (quota per hour), with an Effect
  Allow or Deny, a State active/inactive, a Priority and a Comment.

Decision for a request: gateway or agent suspended -> refusal; an applicable Deny rule covering a cmdlet
of the line -> refusal naming the rule; each cmdlet must be covered by an applicable Allow rule;
authorized vCenters = intersection, over the cmdlets, of the union of the scopes of the rules that cover them; quota
per rule and per agent; single use consumed on successful execution (the rule becomes `exhausted`). Computed states:
active, inactive, suspended, upcoming (shown as "Not yet active"), expired, exhausted, and "active but outside the window".

**Default policy shipped**: `diagnostic` (Get-VIServer and Get-MIThrandirTime for everyone), `read-poc` (broad read
for everyone, to be restricted before production), `perf-forbidden` (example Deny with a time window, inactive),
`access-oneOff-example` (template for temporary single-use access, inactive).

**Console**: pages Rules (state table, full form, enable, suspend, duplicate, reset usage, delete),
Command groups, Scopes, Agents (applicable rules and remaining quota per agent), Simulator (what would
happen for a given agent, a given line, at a given instant: nothing is executed), Global settings, Journal, SIEM export,
Versions (history, restore, advanced JSON editing). Each change creates a version with the Windows author
and an automatic comment; suspensions and usage counters live in `policies\state.json`, outside versions.

## What's new in V3

- **Administration console** on a second port (8766 by default), integrated Windows authentication,
  access restricted to the AD groups in the configuration: dashboard, vCenters, agents, policies, log, export.
- **Versioned policies**: each change from the console creates a version (Windows author, date,
  comment, SHA256), applied hot without restart (engine, typed tools and sandbox lock
  are recomputed). History can be browsed and restored.
- **Suspension**: of the entire gateway (tool calls are refused, the MCP link stays open)
  or of an agent (IP); each refusal returns the reason to the model.
- **Export to security**: Splunk HEC and/or syslog (CEF or JSON) in the background, with a local spool
  and replay if the target is unreachable. CSV/JSONL export on demand from the console.
- Everything done from the console is logged at ADMIN level with the identity of the author.

