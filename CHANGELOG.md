# Changelog

Release numbers map to the project's earlier internal numbering: `Vx.y.z` became `0.xy.z` (V4.8.2 is 0.48.2).
Comments in the code still use the `Vx.y` markers. 0.48.2 was the first public release; earlier entries are
summarized from the internal history.

## 0.49.0

Everything in English. This release is a breaking change for anyone who ran 0.48.2.

- All identifiers are English: script files (`Policy.ps1`, `Sandbox.ps1`, `Sentinel.ps1`, `Scope.ps1`,
  `Catalog.ps1`, `Identity.ps1`, `Inventory.ps1`, `Connection-VCenter.ps1`, `MIThrandir-Relay.ps1`...),
  functions, configuration keys (`MIThrandir.config.psd1`), policy keys and values (`Policy.psd1`, rules,
  command groups, scopes, flags, effects `Allow` / `Deny`), Sentinel levels (`watch`, `restricted`,
  `quarantine`), log levels (`INFO`, `CALL`, `DENIED`, `ERROR`, `ADMIN`, `ALERT`), console API routes and JSON
  fields, and data folders (`policies\`, `inventory\`, `icon\`).
- MCP tools: `Get-HeureMIThrandir` is now `Get-MIThrandirTime`, `Get-MIThrandirCapacites` is
  `Get-MIThrandirCapabilities`, `Get-MIThrandirMesDroits` is `Get-MIThrandirMyRights`. Tool arguments are
  English (for example `Invoke-PowerCLI` takes `Line`). Agents that cached the tool list must call
  `tools/list` again.
- Log messages, refusal reasons, tool descriptions, the console interface, tests and the demo are in English.
- Generic examples replace placeholders that reflected one organization's naming conventions; the console
  marks a vCenter as critical when its name contains `crit`, and treats zones named test, dev, QA, UAT,
  staging, lab or sandbox as outside production.
- `_tests_v46.ps1`: legitimate reads that the default policy does not allow (`Get-View`, `Get-Stat`) are
  reported as prerequisites instead of failures.
- Upgrading from 0.48.2: start from the new `MIThrandir.config.psd1` and `Policy.psd1`, then declare the vCenters
  again from the console. Old `politiques\`, `vcenters\`, `inventaire\` folders and `Identifiant-*.xml` files are
  not read.

## 0.48.2

- The console serves the logo from the `icon/` folder at `/icon/<name>` (GET only, after the usual access
  check). File names are strictly validated: no path, `.png` and `.ico` only, reads limited to that folder.
- Browser tab icon and dashboard logo use `icon/mithrandir-icon.png`.

## 0.48.1

- A client that disconnects before the response is written (Win32 errors 64, 995, 1229, 1236, 10053, 10054,
  `IOException`, `ObjectDisposed`) no longer raises an error with a stack trace: the response is aborted and an
  INFO entry "Response not delivered: client disconnected before processing ended" is logged.
- Unknown `Mcp-Session-Id` now returns HTTP 404, as the MCP specification expects, so a client that survived a
  restart re-runs `initialize` and `tools/list` and sees new tools. Setting `StrictSessions` (default `$true`);
  `$false` restores the old behavior. `MIThrandir-Relay.ps1` handles the 404 by itself and emits
  `notifications/tools/list_changed`.
- Console icons reverted to the vector set of 0.47; the version reported in `serverInfo` and the startup
  banner is aligned.

## 0.48.0

- New dark theme (neutral blue-grey); the light theme is unchanged.
- Console, Rules page: universal search (which rules apply to an object: agent, account, vCenter, scope,
  group, cmdlet, flag) and a composed-target tester.
- Console, Rules page: "From agent activity to a rule" (from the journal to a command group and a draft
  Allow rule).
- Discovery tools for agents: `Get-MIThrandirCapabilities` (engine limits, including objects per response: 25 by
  default, 50 at most) and `Get-MIThrandirMyRights` (resultant set of rights for the calling agent), both in
  the `diagnostic-mithrandir` group and logged at INFO level.

## 0.46.0

Hardening after a review against real-world PowerCLI scripts.

- `Get-View` is allowed but bounded (`Global.Views`): `-Property` is mandatory, object types are allow-listed,
  sensitive property paths are refused in `-Property` and `-Filter` and removed from returned views, views are
  flattened, and scope filtering applies to views as well.
- Six read bypasses closed: wildcards in property names (`N*tes`, `Ext*`), calculated-property values,
  `Where-Object -Property` oracles, `$_.PSObject` access, and the cmdlets `Get-Annotation`,
  `Get-CustomAttribute` and `Get-AdvancedSetting`.
- Load bounds: mandatory targeting for costly cmdlets (`Get-Stat`, `Get-TagAssignment`, `Get-HardDisk`,
  `Get-NetworkAdapter`, `Get-AdvancedSetting`), per-agent sandbox time budget per hour, output size limit.
- Anti-CSRF: `AllowedOrigins` checks the `Origin` header on `/mcp`; the console refuses cross-origin POSTs.
- Monitoring: OpenMetrics endpoint `/metrics` and OTLP/HTTP log export.

## 0.45.0

- vCenters managed from the console (add, edit, reconnect, remove) with hot application. Certificate
  fingerprint verified before saving; per-vCenter credentials encrypted with DPAPI; versioned vCenter list.

## 0.44.0

- Scopes inside vCenters: tags, clusters, folders and VM-name patterns, applied after each PowerCLI cmdlet
  and to the inventory cache.

## 0.43.0

- Command groups from scripts: static (AST) analysis of one or more `.ps1` files proposes a command group and
  an inactive rule flagged "To review".

## 0.42.0

- Sentinel: per-agent suspicion score, levels (watch, restricted, quarantine), automatic suspension,
  protection mode, alert journal, webhook and SMTP alerts, console page.
- Identity: Windows authentication on `/mcp-windows/`, a local relay (`MIThrandir-Relay.ps1`) and HMAC-signed
  assertions from trusted relays.

## 0.41.0

- New console (light/dark, dashboard, rules with flags, scopes, agent cards, journal by source).
- Automatic inventory in a separate process with JSON snapshots, exposed as `Get-MIThrandirInventory`.
- Fix for PowerCLI in ConstrainedLanguage (`$DefaultVIServer` resynchronization).
