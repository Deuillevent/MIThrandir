# Security policy

## Status of this project

MIThrandir is an **experimental, unaudited** security control. It has been tested against vCenter
simulators (vcsim) and against a fake PowerCLI module, and used in a lab. It has **not** been
independently reviewed, and it has not been validated at scale against production vCenter servers.
Do not treat it as your only protection. Always keep the last wall described below.

## What it is meant to protect against

MIThrandir sits between an AI agent (any MCP client) and PowerCLI. The goal is to limit the damage an
agent can do when it drifts, misunderstands a request, or is manipulated by a prompt injection: the agent
can only run what the policy allows, on the objects the policy exposes, within the quotas the policy sets.

Layers, in the order a request meets them:

1. **Policy** (rules per agent, tool, schedule, quota, scope), evaluated before anything runs.
2. **Syntax wall**: every PowerCLI line is parsed (AST, never executed) and checked against cmdlet,
   parameter, property and construct allow/deny lists. `-Server` is forced on every cmdlet.
3. **Sandbox wall**: the line runs in a separate runspace in ConstrainedLanguage mode, with only the
   allowed cmdlets visible, and a time limit.
4. **Bounded output**: sensitive properties are removed (for example `Notes`, `ExtensionData`,
   custom attributes, `guestinfo.*`), results are paginated and size-limited, and scopes (tags,
   clusters, folders, VM names) filter what the agent can see.
5. **Supervision**: Sentinel scores suspicious behavior per agent and can suspend or quarantine it;
   every decision is logged, with optional export to a SIEM (Splunk HEC, syslog/CEF, OTLP).

### The last wall (do this)

Run the vCenter service account with a **read-only vCenter role**, scoped to what the agents need.
Even if every layer above had a flaw, the account should not be able to write. The current default
policy exposes read cmdlets (`Get-*`) only. Opening write actions is a stated goal of the project
but is not a supported configuration yet.

## What it does not protect against

- A compromised MIThrandir host, or an administrator of that host, who can read the DPAPI-protected
  credentials of the account that runs MIThrandir.
- Vulnerabilities in PowerShell, PowerCLI, or vCenter themselves.
- Data that the policy lets the agent read. If an agent may read a property, an injected prompt can
  make the agent repeat it. The policy narrows the blast radius; it does not make an agent trustworthy.
- Network-level exposure. MIThrandir listens on `localhost` by default. Anything beyond that
  (listening on other interfaces, HTTPS, reverse proxies) is your responsibility.

## Known limitations

These were identified during the 0.46 hardening review. Check the CHANGELOG and the code before relying
on the contrary.

- The request loop is single-threaded and the sandbox is a single runspace. A heavy call blocks other
  requests, including the console, until it finishes or hits the time limit.
- The time limit uses `Stop()` on the pipeline, which waits for the in-flight call. A call stuck in a
  vCenter SOAP request can outlive the limit.
- In `Identity.Mode = 'mixed'` (the default), the `/mcp` endpoint accepts anonymous clients identified
  only by IP address. Use `'mandatory'` with Windows authentication or trusted relays in production,
  and set `AllowedIps`, `Token` and `AllowedOrigins`.
- The console uses Windows integrated authentication over HTTP unless you configure HTTPS. Passwords for
  vCenter accounts are accepted over HTTP only from the local machine.
- Certificate pinning protects the vCenter connection only if the first fingerprint you accept is
  correct. Verify it against a trusted source. `-AcceptAnyCertificate` disables pinning and is for
  tests only.
- Stored credentials are encrypted with DPAPI and tied to the Windows account and machine that created
  them.

## Reporting a vulnerability

Please do not open a public issue for a vulnerability. Use GitHub's private vulnerability reporting
("Security" tab of the repository, then "Report a vulnerability"). Include the PowerCLI line or request
that bypasses a control, the policy in effect, and the version. You will get an acknowledgement as soon as
the maintainer can; this is a volunteer project, so no response time is guaranteed.

Bypasses of the syntax wall or the property filters are the most valuable reports. The `_tests_v46.ps1`
script contains the known bypass attempts that are already closed.
