# Contributing

Thanks for your interest. MIThrandir is young and its maintainer works on it in spare time, so please
keep contributions small and focused.

## Before you start

- Open an issue to discuss anything larger than a bug fix.
- Security problems go through the private channel described in [SECURITY.md](SECURITY.md), not a public issue.

## License of contributions

MIThrandir is published under MIT with the Commons Clause (see [LICENSE](LICENSE)). By submitting a
contribution you agree that it is licensed under the same terms, and you grant the maintainer the right to
relicense the project, including your contribution, in the future. If you cannot accept this, please do not
submit code; issues and ideas are always welcome.

## Conventions

- **PowerShell 7+ only**, no external dependencies besides PowerCLI.
- **Comments and documentation in English.**
- **Everything is in English**: identifiers, configuration and policy keys, MCP tool names and arguments, log
  messages and the console UI. Plain ASCII in code and messages.
- Refusal reasons are matched by regular expressions (Sentinel categories in `Sentinel.ps1`, tests). If you
  change the wording of a refusal reason, update those patterns in the same change.
- Version markers like `V4.6` in comments are the project's historical numbering. `Vx.y` corresponds to
  release `0.xy.0` (for example V4.8.2 is 0.48.2).
- Every change that affects what an agent may do must come with a test. Add refusal cases to
  `_tests_v46.ps1` (bypass attempts) or to a new test script next to it.
- Do not commit runtime data (logs, inventory, credentials, policy history). The `.gitignore` covers them.

## Running the checks

1. Start a vCenter simulator and MIThrandir as described in [demo/README.md](demo/README.md).
2. Run `./_tests_v46.ps1` and `./Test-MIThrandir.ps1` against the running instance.
3. Parse all scripts for syntax errors before opening a pull request:

```powershell
Get-ChildItem -Recurse -Include *.ps1 | ForEach-Object {
    $tokens = $null; $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { "$($_.Name): $($errors[0].Message)" }
}
```
