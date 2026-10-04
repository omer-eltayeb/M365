# Contributing

Thanks for taking the time to improve these scripts. Issues, ideas and pull requests are welcome.

## Reporting a problem
Open an issue and include:
- the script name and version (see the `.NOTES` block in the script header),
- PowerShell version (`$PSVersionTable.PSVersion`) and module versions (`Get-Module -ListAvailable Microsoft.Graph.Authentication, ExchangeOnlineManagement`),
- the exact command you ran (remove tenant names, UPNs and IDs),
- the full error text.

## Submitting a change
1. Fork the repository and create a branch (`feature/get-intune-something`).
2. Follow the conventions below so the repository stays consistent.
3. Run `Invoke-ScriptAnalyzer -Path . -Recurse -Settings ./PSScriptAnalyzerSettings.psd1` locally and fix any **Error** findings.
4. Open a pull request that explains *what* changed and *why*; link the issue if there is one.

## Conventions
- **Read-only by default.** Anything that changes a tenant must sit behind an explicit switch, use
  `SupportsShouldProcess` with `ConfirmImpact = 'High'`, and wrap each change in `$PSCmdlet.ShouldProcess()`.
- **Comment-based help** (`.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, `.EXAMPLE`, `.NOTES` with `Permissions`, `Category` and `Changes` fields, `.LINK`) on every script.
  The folder READMEs and the root script index are generated from these fields, so keep them accurate.
- **Compatibility:** Windows PowerShell 5.1 and PowerShell 7.x. No PowerShell 7-only syntax (ternary, `??`, `ForEach-Object -Parallel`).
- **Microsoft Graph** via `Microsoft.Graph.Authentication` + `Invoke-MgGraphRequest`; v1.0 unless beta is the only option (then say so in the header). **Exchange / Purview** via `ExchangeOnlineManagement` v3.
- **Style:** approved verbs, full cmdlet names (no aliases), named parameters, 4-space indentation, `[PSCustomObject]` output with PascalCase property names, `-OutputPath` / `-PassThru` on every report.
- **Never** hard-code tenant IDs, app IDs, secrets or user names, and never call `Install-Module` from a script.

## Code of conduct
Be kind, be constructive, assume good intent.
