<#
.SYNOPSIS
    Installs or updates the PowerShell modules required by the scripts in this repository.
.DESCRIPTION
    Checks whether the Microsoft Graph PowerShell SDK authentication module (Microsoft.Graph.Authentication)
    and the Exchange Online Management module (ExchangeOnlineManagement) are installed, installs anything
    that is missing from the PowerShell Gallery, and optionally updates existing installs to the latest
    release. With -IncludeDevTools it also installs PSScriptAnalyzer, which the repository's CI workflow uses.

    Nothing is installed without your confirmation unless you pass -Confirm:$false, and -WhatIf shows the
    plan without changing anything.
.PARAMETER Scope
    Installation scope passed to Install-Module. CurrentUser (default) needs no elevation; AllUsers requires
    an elevated session.
.PARAMETER Update
    Update modules that are already installed to the newest version available in the PowerShell Gallery.
.PARAMETER IncludeDevTools
    Also install PSScriptAnalyzer for local linting.
.EXAMPLE
    PS> .\Install-Prerequisites.ps1
    Installs any missing module for the current user.
.EXAMPLE
    PS> .\Install-Prerequisites.ps1 -Update -IncludeDevTools -Verbose
    Installs or updates every module, including PSScriptAnalyzer, and shows what happens along the way.
.EXAMPLE
    PS> .\Install-Prerequisites.ps1 -WhatIf
    Shows which modules would be installed or updated without doing it.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-03
    Requires    : PowerShell 5.1 or 7.x, internet access to https://www.powershellgallery.com
    Permissions : None in Microsoft 365; local admin only when -Scope AllUsers is used
    Category    : Tools
    Changes     : Local machine only
    Notes       : On Windows PowerShell 5.1 make sure TLS 1.2 is enabled for the Gallery (the script sets it for
                  the current session). If PowerShellGet is very old, run
                  'Install-Module PowerShellGet -Force' first and restart the console.
.LINK
    https://learn.microsoft.com/powershell/microsoftgraph/installation
.LINK
    https://learn.microsoft.com/powershell/exchange/exchange-online-powershell-v2
#>
#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter()]
    [ValidateSet('CurrentUser', 'AllUsers')]
    [string]$Scope = 'CurrentUser',

    [Parameter()]
    [switch]$Update,

    [Parameter()]
    [switch]$IncludeDevTools
)

$ErrorActionPreference = 'Stop'

#region Main
$requiredModules = @(
    [PSCustomObject]@{ Name = 'Microsoft.Graph.Authentication'; Purpose = 'Microsoft Graph sign-in and Invoke-MgGraphRequest' }
    [PSCustomObject]@{ Name = 'ExchangeOnlineManagement';       Purpose = 'Exchange Online and Security & Compliance PowerShell' }
)
if ($IncludeDevTools) {
    $requiredModules += [PSCustomObject]@{ Name = 'PSScriptAnalyzer'; Purpose = 'Local linting (same rules as the CI workflow)' }
}

# Windows PowerShell 5.1 defaults to older TLS versions that the PowerShell Gallery no longer accepts.
if ($PSVersionTable.PSVersion.Major -lt 6) {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
}

$results = foreach ($module in $requiredModules) {
    $installed = Get-Module -Name $module.Name -ListAvailable | Sort-Object -Property Version -Descending | Select-Object -First 1
    $action = 'None'
    $versionAfter = $null

    try {
        if ($null -eq $installed) {
            if ($PSCmdlet.ShouldProcess($module.Name, "Install module ($Scope)")) {
                Write-Verbose "Installing $($module.Name) ..."
                Install-Module -Name $module.Name -Scope $Scope -Repository PSGallery -Force -AllowClobber
                $action = 'Installed'
            }
        }
        elseif ($Update) {
            $latest = Find-Module -Name $module.Name -Repository PSGallery
            if ($latest.Version -gt $installed.Version) {
                if ($PSCmdlet.ShouldProcess($module.Name, "Update $($installed.Version) -> $($latest.Version)")) {
                    Write-Verbose "Updating $($module.Name) from $($installed.Version) to $($latest.Version) ..."
                    Install-Module -Name $module.Name -Scope $Scope -Repository PSGallery -Force -AllowClobber
                    $action = 'Updated'
                }
            }
            else {
                $action = 'UpToDate'
            }
        }
        else {
            $action = 'AlreadyInstalled'
        }
    }
    catch {
        Write-Warning "Could not process $($module.Name): $($_.Exception.Message)"
        $action = 'Failed'
    }

    $current = Get-Module -Name $module.Name -ListAvailable | Sort-Object -Property Version -Descending | Select-Object -First 1
    if ($null -ne $current) { $versionAfter = $current.Version.ToString() }

    [PSCustomObject]@{
        Module  = $module.Name
        Purpose = $module.Purpose
        Action  = $action
        Version = $versionAfter
    }
}

Write-Host ''
Write-Host 'Prerequisite check' -ForegroundColor Cyan
$results | Format-Table -AutoSize | Out-String | Write-Host
if (@($results | Where-Object { $_.Action -eq 'Failed' -or $null -eq $_.Version }).Count -gt 0) {
    Write-Warning 'At least one module is missing. Re-run the script in an elevated session or check your Gallery connectivity.'
}
#endregion Main
