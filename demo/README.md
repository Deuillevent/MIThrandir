# Demo: MIThrandir against a vCenter simulator

This walkthrough needs no real vCenter. It uses `vcsim`, the vCenter simulator of the
[govmomi](https://github.com/vmware/govmomi) project, on a Windows machine.

## Prerequisites

- Windows with PowerShell 7+ and VMware PowerCLI 13.3 (`Install-Module VMware.PowerCLI`).
- The `vcsim` executable (download it from the govmomi releases on GitHub).

## Steps

1. **Start the simulator** (leave this window open):

   ```powershell
   .\demo\Start-Vcsim.ps1 -VcsimPath C:\Tools\vcsim.exe
   ```

   It listens on `127.0.0.1:8989` with 30 VMs and the account `user` / `pass`.

2. **Start MIThrandir** in a second window, from the repository root:

   ```powershell
   pwsh -NoProfile -File .\MIThrandir-MCP.ps1 -WithVCenter
   ```

   The default configuration listens on `localhost` only (MCP on 8765, console on 8766). With no vCenter
   declared yet, it starts anyway and says so in the log.

3. **Declare the simulator** from the console. The console only lets in local administrators by default.
   Either start MIThrandir from an elevated PowerShell, or put your account in `Console.AllowedUsers`
   (for example `@('MACHINE\you')`) in `MIThrandir.config.psd1` before step 2. Then open
   `http://localhost:8766/` on the same machine, go to
   "Global settings", "vCenters" tab, click "Add a vCenter" and enter:
   - short name `demo`, server `127.0.0.1`, port `8989`;
   - click "Read the certificate": vcsim uses a self-signed one, check that the displayed
     thumbprint matches what you expect;
   - service account `user`, password `pass`, then "Save and connect".

   Password entry is only accepted over HTTPS or from the local machine, which is why this step is done on
   the machine that runs MIThrandir.

4. **Replay agent requests**:

   ```powershell
   .\demo\Demo-Lines.ps1
   ```

   The script sends allowed lines (read-only listings) and forbidden ones (power off, method calls,
   hidden-property tricks) and prints the expected and observed outcome next to each line, with the refusal
   reason. Open the console while it runs: the dashboard shows the live stream and the journal records every
   decision. Add `-Full` for more refused lines; after a few refusals in a row, Sentinel restricts the
   agent and the script reports those lines as blocked by the Sentinel rather than by the syntax wall.

5. **Go further**: use the "Simulator" page to test what would happen for a given agent and line without
   executing anything, create a scope by tag or cluster, or point an MCP client (Streamable HTTP transport,
   URL `http://localhost:8765/mcp`) at the gateway and ask it to list VMs.

Note: Sentinel restricts, then quarantines, an agent that triggers many refusals in a short time. If calls
keep being refused after a demo run, release the agent from the Sentinel page of the console. The state is kept
across restarts (`journal\sentinel.json`), so restarting MIThrandir alone does not clear it.

## Status of this demo

The scripts in this folder were written for the repository's first public release. If a step does not work
as described, please open an issue with the console journal lines.
