# MIThrandir

**A policy-enforcing MCP gateway that lets AI agents use VMware PowerCLI without handing them the keys.**

Version 0.49.0 (experimental). Windows, PowerShell 7+, PowerCLI 13.3.
License: MIT with the Commons Clause (see [LICENSE](LICENSE)).

An AI agent that can write PowerCLI is useful, and dangerous when it drifts, misreads a request, or is
manipulated by a prompt injection. MIThrandir sits between any MCP client and your vCenter servers.
The agent writes ordinary PowerCLI (one line, pipelines included), and every line is checked before it runs.

What it does:

- **Two independent walls before execution**: the line is parsed (AST, never executed) against cmdlet,
  parameter, property and construct lists; then it runs in a separate ConstrainedLanguage runspace where
  only allowed cmdlets exist, with a time limit.
- **A rules engine**: who (agent, account, AD group), what (command groups), where (vCenters and scopes by
  tag, cluster, folder or VM name), when (time windows), how much (quotas, usage limits, sandbox time budget).
- **Redaction**: sensitive properties (`Notes`, `ExtensionData`, custom attributes, `guestinfo.*`...) never
  reach the model, and results are bounded in count and size.
- **Supervision**: a per-agent suspicion score with automatic suspension and quarantine, a full journal,
  and export to Splunk, syslog/CEF or OpenTelemetry.
- **An administration console** (versioned policies, simulator, rule search, live flow) and a cached
  inventory for bulk read questions.

## License

MIThrandir is **source available**, not open source in the OSI sense. You may use it freely, including
inside a for-profit company or a public body, read it, modify it, and share it. You may **not sell it**: the
Commons Clause removes the right to provide to third parties, for a fee or other consideration, a product or
service whose value derives substantially from MIThrandir. That includes reselling, bundling it in a paid
product, offering it as a hosted service, and paid hosting, consulting or support services related to it.
This is a summary; the text of [LICENSE](LICENSE) is what applies.

## Status

Experimental and unaudited. It has been tested against vCenter simulators and a lab, not independently
reviewed. In this release agents get read access (`Get-*`); opening controlled write actions is a goal, not
a supported configuration. Always run the vCenter service account with a read-only role as the last wall.
Read [SECURITY.md](SECURITY.md) before exposing it to anything you care about.

Language: since 0.49.0 everything is in English: code, identifiers, configuration and policy keys, MCP tool
names and arguments, log messages and the console. Release 0.48.2 was the last one with French identifiers and
interface; its configuration, policy and data files are not compatible with 0.49.0 (see CHANGELOG.md).

## Try it in 10 minutes

You do not need a vCenter: see [demo/README.md](demo/README.md) for a walkthrough with a vCenter simulator
(vcsim) that shows allowed and refused lines.

## Related projects

To our knowledge, as of November 2026, other open vSphere and PowerShell MCP servers take a different path:
they expose a fixed set of tools over the vSphere API (for example
[InfraMCP/vsphere-mcp-server](https://github.com/InfraMCP/vsphere-mcp-server) and
[TheEvalon/vmware-vcenter-mcp](https://github.com/TheEvalon/vmware-vcenter-mcp), the latter with a dry-run
confirmation and a read-only switch), or run PowerShell with a language mode and allow/block lists
([mcp-server-for-powershell](https://glama.ai/mcp/servers/danielklecha/mcp-server-for-powershell),
[PoshMCP](https://mcpservers.org/th/servers/cezarypiatek/poshmcp)). MIThrandir's focus is different: free-form
PowerCLI under per-agent policy, with auditing. Corrections welcome.

## Documentation map

- [SECURITY.md](SECURITY.md): threat model, limits, reporting.
- [CHANGELOG.md](CHANGELOG.md): releases. [docs/HISTORY.md](docs/HISTORY.md): detailed notes of earlier versions.
- [CONTRIBUTING.md](CONTRIBUTING.md): conventions and checks.
- The rest of this file: architecture, installation, usage, policy, console, troubleshooting.

## How it works


Agents are not constrained by the shape of the tools: they write PowerCLI (a single line, pipelines included) or
call `Get-*` tools whose schema is generated from the installed cmdlet. The filtering happens elsewhere: two
independent walls, both BEFORE execution.

```
agent  ->  MCP  ->  policy (tool, agent, time window, quota)
                ->  WALL 1: syntactic analysis (AST) of the line: cmdlets, parameters, constructs, vCenters
                ->  rewrite: -Server forced on every cmdlet that does not specify it
                ->  WALL 2: sandbox (separate runspace, cmdlets outside the list invisible, ConstrainedLanguage, timeout)
                ->  bounded projection of results (excluded properties, pagination, maximum size)
```

```
MIThrandir\
  MIThrandir-MCP.ps1        server: MCP listener (/mcp) + console listener, main loop
  MIThrandir.config.psd1    listening, MCP clients, vCenters, PowerCLI modules, console, SIEM export
  Policy.psd1               initial global settings (V3); on first start, imported into the default V4 policy
  Console.html              administration console page (no external resource)
  policies\                 versioned repository: active.json + history\vNNNNN.json (created on first start)
  Policy.ps1                rules engine: global settings, command groups, scopes, rules, decision, simulator
  Connection-VCenter.ps1    one DPAPI-encrypted credential and one pinned certificate per vCenter
  Sandbox.ps1               locked-down execution runspace, vCenter sessions, result projection
  Validation-AST.ps1        syntactic validation of each PowerCLI line
  Catalog.ps1               Invoke-PowerCLI, Get-VIServer, Get-MIThrandirTime, generated typed tools
  Journal.ps1               local log, in-memory buffer for the console, counters, asynchronous Splunk HEC / syslog export
  Console.ps1               administration console: JSON API + standalone HTML page
  Test-MIThrandir.ps1       test client
  vcenters\                 vCenter list managed by the console (vcenters.json + history\vNNNNN.json)
                            and one Credential-<name>.xml (DPAPI) per vCenter entered in the console
  icon\                     MIThrandir icon (png 32/64/256, ico)
  journal\                  one JSONL per day; journal\spool\: events not delivered to the SIEM, replayed
```


## 1. Installation on a production server

MIThrandir is portable (no installer, only PowerShell), but it is not "copy then run": it needs
PowerCLI, a service account, the HTTP listener and its vCenter credentials. Recommended order:

1. **Offline prerequisites**: PowerShell 7 (MSI) and PowerCLI 13.3. On a connected machine:
   `Save-Module VMware.PowerCLI -Path C:\Transfer -RequiredVersion 13.3.0`, then copy the resulting folders into
   `C:\Program Files\PowerShell\Modules` on the server.
2. **Service account** (gMSA or domain account) that will run MIThrandir. On each vCenter: an account with a read-only
   role during the test phase (this account is then entered in the console, step 7).
3. **Copy the contents of the zip** (for example to `D:\MIThrandir`). Do not carry over anything from a test bench: the
   `Credential-*.xml` files (DPAPI-encrypted for another account and another machine, hence unreadable), `vcenters\`,
   `inventory\`, `journal\` and the `_*.ps1` scripts. The `policies\` repository can be carried over to keep a policy.
4. **`MIThrandir.config.psd1`**:
   - `Address = '+'`, `AllowedIps` (WebUI, relay), `Token`;
   - `VCenters = @()`: the list is built in the console (step 7);
   - `Console`: `Address = '+'`, `Https = $true`, AD group in `AllowedGroups`, `AllowedUsers = @()`;
   - `Identity.Mode` (`mandatory` in production), `Identity.Relay` with the IP of the trusted front end;
   - `Export.Splunk` / `Export.Syslog`, `Alerts`.
5. **Windows** (once, as administrator):
   ```powershell
   netsh http add urlacl url=http://+:8765/ user="DOMAIN\svc-mithrandir$"
   netsh http add urlacl url=https://+:8766/ user="DOMAIN\svc-mithrandir$"
   netsh http add sslcert ipport=0.0.0.0:8766 certhash=<machine certificate thumbprint> appid={<a GUID>}
   New-NetFirewallRule -DisplayName "MIThrandir MCP 8765" -Direction Inbound -Protocol TCP -LocalPort 8765 -Action Allow
   New-NetFirewallRule -DisplayName "MIThrandir console 8766" -Direction Inbound -Protocol TCP -LocalPort 8766 -Action Allow
   [Environment]::SetEnvironmentVariable('MITHRANDIR_SECRET_RELAY', '<secret shared with the front end>', 'Machine')
   ```
6. **Startup**: a scheduled task "At system startup", run under the service account, action
   `pwsh.exe -NoProfile -ExecutionPolicy Bypass -File D:\MIThrandir\MIThrandir-MCP.ps1 -WithVCenter`, restart on
   failure. On first launch with no vCenter, MIThrandir still starts and announces it (ALERT level).
7. **vCenters from the console** (`https://mithrandir-01.example.local:8766/`, "Global settings" page, "vCenters" tab): for each one,
   short name, zone, server, *Read the certificate* (check the thumbprint), service account and password, *Save and
   connect*. It is the MIThrandir process, hence the service account, that encrypts the password: no
   interactive session under the gMSA is needed.
8. Verify: dashboard (connected vCenters, inventory), then `Test-MIThrandir.ps1` from an authorized machine.

On first start, `Policy.psd1` is migrated into version 1 of the `policies\` repository; after that the repository
is authoritative and `Policy.psd1` is no longer read. Likewise, the `VCenters` block of the psd1 is imported once into
`vcenters\vcenters.json`, then ignored.

The former modes `-ShowCertificate` and `-SaveCredential` still exist (they work on the repository's
list); `-SaveCredential` must be run under the service account.

At startup: policy loaded (SHA256), sandbox created (PowerCLI modules imported), certificate and
connection per vCenter, then "Sandbox locked" with the number of commands left visible, then the
catalog. Without `-WithVCenter`, only `Get-MIThrandirTime` is exposed.

## 2. What the agent can do

### Invoke-PowerCLI

A PowerCLI line, pipeline accepted:

```
Get-VM -Name 'TST-*' -Server vc-test | Select-Object Name, PowerState, NumCpu, MemoryGB
Get-Cluster CL-TEST | Get-VMHost | Get-Datastore | Where-Object FreeSpaceGB -lt 100 | Sort-Object FreeSpaceGB
Get-VM TST-WEB01 | Get-Snapshot | Select-Object Name, Created, SizeGB
Get-VMHost | Where-Object { $_.ConnectionState -ne 'Connected' } | Select-Object Name, ConnectionState, Parent
Get-Datastore | Select-Object Name, @{ N = 'LibrePct'; E = { [math]::Round(100 * $_.FreeSpaceGB / $_.CapacityGB) } }   # REFUSED: [math] is a type
```

Allowed: cmdlets of the `VMware.*` modules that match `AllowedCmdlets` (`Get-*` by default)
and are not in `ExcludedCmdlets`; utilities `Where-Object`, `Select-Object`, `Sort-Object`,
`Group-Object`, `Measure-Object`; cmdlet parameters (unambiguous abbreviations accepted) except
`ExcludedParameters`; constants, arrays, script blocks inside a utility with `$_`, properties,
indexes, comparisons and logical operators.

Refused (before any execution, with the reason returned to the model): assignments, loops, conditionals,
functions, `[types]`, method calls, `$( )`, variables, `&`, redirections, splatting, `&&`/`||`,
strings with nested expressions, unknown or out-of-list commands, common parameters except
`-ErrorAction`, excluded parameters, `-Server` to an unauthorized vCenter, any reference to a
property of `ExcludedProperties` (including via `Select-Object -ExpandProperty`).

Without `-Server`, MIThrandir adds `-Server` with the vCenters authorized for the agent on every PowerCLI
cmdlet of the line (the rewritten line is logged). Each returned object carries `vcenter`.

### Typed tools (Get-VM, Get-VMHost, ...)

For the cmdlets in `Policy.TypedTools`, one MCP tool per cmdlet, with a schema generated at startup from
`Get-Command`: same parameter names, types (string, integer, boolean, enum, `ValidateSet`),
mandatory parameters of the default parameter set, PowerCLI object parameters accepted by name (Object-By-Name,
wildcards included), plus a `Limit` specific to MIThrandir. The call is converted into a PowerCLI line and goes through the
same path as `Invoke-PowerCLI`. Changing the PowerCLI version updates the schemas without touching the code.

### Get-VIServer, Get-MIThrandirTime

List of the vCenters visible to the agent (short names for `-Server`), and link diagnostics.

## 3. Policy (`policies\` repository, edited from the console)

| Key | Purpose |
|---|---|
| `AllowedCmdlets` | patterns of executable PowerCLI cmdlets (`Get-*`) |
| `ExcludedCmdlets` | refused despite the pattern (`Get-EsxCli`, `Get-View`, `Get-VIEvent`, ...) |
| `Utilities` | PowerShell formatting cmdlets accepted in a pipeline |
| `ExcludedParameters`, `ExcludedParametersPerCmdlet` | refused parameters (`Id`, `RelatedObject`, `Tag`, ...) |
| `ExcludedProperties` | properties never returned nor referenceable (`Notes`, `CustomFields`, ...) |
| `TypedTools` | cmdlets also exposed as MCP tools with a schema |
| `MaxBatchSize`, `DefaultBatchSize`, `MaxOutputSize`, `MaxDelaySeconds` | limits |
| `TimeRange`, `CallQuotaPerHour` | time window and quota |
| `Agents.<ip>` | authorized `Tools`, `Cmdlets`, `VCenters` for this agent; `default` otherwise |

The sandbox is locked according to `AllowedCmdlets`, `ExcludedCmdlets` and `Utilities`: what is not in
them no longer exists in the execution runspace, even if the AST validation had a flaw.
Per-agent rights (`Agents.<ip>.Cmdlets`) are enforced by the AST validation.

From the console, the pages of the "Policy" section (Rules, Command groups, Scopes, Simulator, Global settings) edit the
policy; on the "Versions" page, the full JSON of the active policy is also editable ("Advanced editing"). "Validate and apply"
checks consistency (mandatory keys, numbers, time range, Get-* patterns only), creates the next version
in `policies\history\`, writes it to `active.json` and applies it hot. A rejected policy changes nothing.
The history lets you view each version and restore it (which creates a new version; the history is never rewritten).

Outside the console, the same can be done by editing `policies\active.json` and then restarting MIThrandir,
but without author or comment: reserve this for troubleshooting.

To open `Get-View` (access to the whole API): remove it from `ExcludedCmdlets` and restrict its
parameters in `ExcludedParametersPerCmdlet`; `-ViewType` and `-Filter` remain read-only, but the volume
returned can be very large.

## 4. Administration console (`http://mithrandir-01.example.local:8766/`)

| Page | Content | Actions |
|---|---|---|
| Dashboard | gateway state, vCenters, sandbox (locked, visible commands), counters, latest events | suspend / resume the gateway, reconnect a vCenter |
| Agents | declared and observed IPs, effective rights, calls, refusals, errors, remaining quota, last command | suspend / resume an agent |
| Versions | policy history, version metadata, JSON of the active policy | validate and apply a new version, view or restore an old one |
| Journal | in-memory events (last 5,000), filters by level / agent / text, live mode | CSV or JSONL export |
| SIEM export | export state (sent, failures, pending, spool, last error) | send a test event |

The other pages (Inventory, Sentinel, Rules, Command groups, Scopes, Simulator, Global settings) are described in
[docs/HISTORY.md](docs/HISTORY.md).

The JSON API behind the page (`/api/state`, `/api/agents`, `/api/policy`, `/api/journal`, ...) can be used
from a PowerShell script with `Invoke-RestMethod -UseDefaultCredentials`, for example to monitor MIThrandir.

Console security: integrated Windows authentication mandatory, no local account in the console;
`Https = $true` with a certificate bound to the port (`netsh http add sslcert`) as soon as the console leaves the
administration network; `Address = 'localhost'` to restrict it to the machine (access via RDP).

## 5. Export to Splunk or a SIEM

`Export` section of `MIThrandir.config.psd1`. Both targets can be active at the same time.

- **Splunk HEC**: collector `Url` (`.../services/collector/event`), `Token`, `Index`, `SourceType`.
  Events are sent as structured JSON (level, agent, message, data: PowerCLI line, refusal reason,
  vCenters queried, author of admin actions...). Starting Splunk query: `index=infra sourcetype=mithrandir:json level=DENIED`.
- **Syslog**: `Host`, `Port`, `Protocol` (udp, or tcp with RFC 6587 framing), `Format`:
  `cef` (header `CEF:0|MIThrandir|MIThrandir|0.49.0|<level>|<message>|<severity>|...` with `src`, `msg`, `cs_line`,
  `cs_reason`, `cs_author`...) for ArcSight, Sentinel, QRadar; or `json` (the raw line).
- Asynchronous sending in batches of 100, MIThrandir never blocks. On failure, the batch is written to
  `journal\spool\` and replayed as soon as the target responds; the console's "SIEM export" page shows the state.
- The local JSONL file (`journal\mithrandir-YYYYMMDD.jsonl`) is written in all cases.

Exported levels: INFO (initializations, connections, policies), CALL (each execution, with the rewritten line
and the vCenters), DENIED (with the reason), ERROR, ADMIN (actions done from the console, with the author).

## 6. Declaration in the llama-server WebUI

Two ways:

1. **Configuration file** (recommended, zero clicks): create a `llama-webui.json` file (not shipped in this release). `mcpServers` is
   a JSON string in it (format expected by the WebUI) with `id`, `name`, `url`, `useProxy`, `enabled`. Launch:
   `llama-server.exe -m model.gguf --jinja --host 0.0.0.0 --port 8080 --ui-mcp-proxy --webui-config-file llama-webui.json`.
   Note: the WebUI applies these values only to a browser with no saved configuration; on a browser
   already in use, reset the default settings (Settings, Reset) or clear the site's local storage.
2. **By hand**: gear icon, MCP, Add New Server, Streamable HTTP, `http://<host>:8765/mcp`, Use llama-server proxy.

On each tool call, the WebUI asks for confirmation (Allow once / Allow always): this is its own safeguard,
independent of MIThrandir.

### Previous procedure

```
llama-server.exe -m model.gguf --jinja --host 0.0.0.0 --port 8080 --ui-mcp-proxy
```

WebUI: gear icon, MCP, Add New Server, Streamable HTTP, `http://<host>:8765/mcp`, enable.
"Failed to fetch": enable "Use llama-server proxy" (the IP of the llama-server VM then goes into
`AllowedIps` and `Agents`). Token: header `Authorization: Bearer <token>` on the server entry.
After a policy change: restart MIThrandir, disable then re-enable the server in the WebUI.

## 7. Tests without a browser

```powershell
.\Test-MIThrandir.ps1 -Tool Get-VIServer
.\Test-MIThrandir.ps1 -Tool Get-VM -Arguments @{ Name = 'TST-*'; Server = 'vc-test'; Limit = 5 }
.\Test-MIThrandir.ps1 -Tool Invoke-PowerCLI -Arguments @{ Line = "Get-Cluster CL-TEST | Get-VMHost | Select-Object Name, ConnectionState, Version" }
.\Test-MIThrandir.ps1 -Tool Invoke-PowerCLI -Arguments @{ Line = 'Get-VM | ForEach-Object { Remove-VM $_ }' }   # refused: ForEach-Object is not in the utilities, Remove-VM is not in the list
.\Test-MIThrandir.ps1 -Tool Invoke-PowerCLI -Arguments @{ Line = '$x = Get-VM; $x' }                              # refused: assignment
.\Test-MIThrandir.ps1 -Tool Invoke-PowerCLI -Arguments @{ Line = 'Get-VM | Select-Object -ExpandProperty Notes' } # refused: excluded property
```

Each refusal appears as `[DENIED]` in the console with the reason, and the reason is returned to the model.

## 8. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `Sandbox preparation: ...` | PowerCLI module missing or incomplete | check the modules of `PowerCliModules` in `C:\Program Files\PowerShell\Modules` |
| `Sandbox locked` with a small number of visible commands | normal: only the allowed cmdlets remain | none |
| `line denied by MIThrandir: unknown command: X` | alias or cmdlet absent from the sandbox | write the full name; check the module |
| `line denied by MIThrandir: parameter -X denied on <cmdlet>` | `ExcludedParameters` | adjust the policy if legitimate |
| `timeout of N s exceeded, execution interrupted` | request too broad | target with `-Server`, `-Name`, `-Location` or `Limit` |
| `[output truncated at N characters by MIThrandir; ...]` | too many properties or objects | targeted `Select-Object`, lower `Limit` |
| Slow responses on 7 vCenters | line without `-Server` | specify `-Server`; the model learns quickly with `Get-VIServer` |
| Console: endless 401 or credential prompt | site outside the intranet zone, or missing Kerberos SPN | add `http://mithrandir-01.example.local` to the intranet zone; NTLM takes over otherwise |
| Console: `access denied` | user outside `AllowedGroups` and `AllowedUsers` | see the line `[DENIED] Console: access denied (...)` in the journal |
| Export: `failures` increases, files in spool | Splunk/SIEM unreachable or invalid token | `lastError` on the "SIEM export" page; the spool is replayed automatically |
| Policy rejected at validation | invalid JSON or consistency rule | the message says which key; nothing was applied |
| `no rule allows X for this subject` | no active Allow rule covering X for this agent | "Rules" page; the Simulator shows the applicable rules |
| `vCenter X outside the scope of your rules for <cmdlets>` | -Server outside the intersection of the scopes | add a scope to the rule, or remove -Server |
| Rule shown as "Active" with "outside window" | days or hours of the rule | normal; the Simulator with a future instant verifies it |
| `Invoke-RestMethod` blocked on the console from pwsh | Windows authentication over HTTP | add `-AllowUnencryptedAuthentication`, or use `curl.exe --negotiate -u :` |

## 9. Validated on a test bench (30 October 2026)

On a Windows 11 PC with PowerShell 7.6.9, PowerCLI 13.3, two vCenter simulators (vcsim 0.56.2, 30 and 1,080 VMs,
distinct accounts and certificates), llama-server b12017 CUDA with Qwen3-4B-Instruct:

- 29 MCP tests (12 allowed lines, 17 refused constructs): 29/29;
- rule scenarios (scope per agent, priority Deny, time window, single use, suspension,
  inconsistency validation, versions): all compliant;
- llama-server WebUI pre-declared by file, Qwen chose Get-VIServer then a PowerCLI pipeline and answered
  correctly; a Stop-VM request and a Get-Snapshot forbidden by a rule were refused before execution.

## 10. Next steps

- V3.1 load: sandbox pool, asynchronous HTTP, Get-View inventory cache refreshed continuously,
  quotas in objects and seconds, mandatory targeting on heavy cmdlets.
- Scopes by vCenter tag (application, environment) attached to agents, editable in the console.
- Tier C: sandbox moved out of the process (JEA, gMSA), credentials moved out of the facade.
- Windows service (NSSM or sc.exe) so that MIThrandir starts with the machine.
