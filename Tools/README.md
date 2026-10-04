# Tools scripts

Helper scripts for the repository itself.

**1 scripts.** Module(s): PowerShellGet.

Every script has full comment-based help (`Get-Help .\<Script>.ps1 -Full`), writes a timestamped CSV to `.\Reports\` by default (`-OutputPath` to choose, `-PassThru` to keep the objects) and is read-only unless the **Changes anything?** column says otherwise - those scripts support `-WhatIf` / `-Confirm`.

## Contents

- [Tools](#tools) (1)

## Tools

| Script | What it does | Permissions / roles | Changes anything? |
|---|---|---|---|
| [Install-Prerequisites.ps1](./Install-Prerequisites.ps1) | Installs or updates the PowerShell modules required by the scripts in this repository. | None in Microsoft 365; local admin only when -Scope AllUsers is used | Local machine only |

## Quick start

```powershell
# Install-Prerequisites.ps1
.\Install-Prerequisites.ps1 -WhatIf
```

---

Back to the [repository overview](../README.md).
