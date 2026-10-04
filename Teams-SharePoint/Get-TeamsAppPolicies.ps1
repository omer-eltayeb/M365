<#
.SYNOPSIS
    Reports the Teams app permission and app setup policies, the org-wide custom app setting and how many users each policy has.
.DESCRIPTION
    Reads Get-CsTeamsAppPermissionPolicy (per catalog: Microsoft, third-party and custom apps, allow or block list mode and
    the app IDs), Get-CsTeamsAppSetupPolicy (user pinning, custom app upload, pinned app bar and message extension apps,
    installed apps) and Get-CsTeamsSettingsCustomApp (org-wide custom app interaction switch). With -IncludeUserCounts one
    Get-CsOnlineUser enumeration adds the number of users directly assigned to each policy. Permission policies are
    exported to the main CSV and setup policies to <name>_SetupPolicies.csv. Flags mark setup policies that allow custom
    app upload (sideloading) and permission policies that allow every third-party or custom app.
.PARAMETER IncludeUserCounts
    Count the users directly assigned to each policy (one enumeration of all users; several minutes in large tenants).
.PARAMETER OutputPath
    Path of the permission policy CSV (default .\Reports\TeamsAppPolicies_<timestamp>.csv); <name>_SetupPolicies.csv is written next to it.
.PARAMETER PassThru
    Also emit the permission and setup policy objects to the pipeline (property PolicyKind tells them apart).
.EXAMPLE
    PS> .\Get-TeamsAppPolicies.ps1
    Exports both policy types and prints which policies allow sideloading or all third-party apps.
.EXAMPLE
    PS> .\Get-TeamsAppPolicies.ps1 -IncludeUserCounts -OutputPath C:\Temp\AppPolicies.csv -Verbose
    Adds the number of users per policy so unused custom policies can be cleaned up.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, MicrosoftTeams
    Permissions : Teams Administrator or Global Reader (read-only).
    Category    : Teams administration (MicrosoftTeams module)
    Changes     : No
    Notes       : Tenants migrated to app centric management (Teams admin center > Teams apps > Manage apps) no longer enforce
                  app permission policies; Get-CsTeamsAppPermissionPolicy then returns the legacy, read-only definitions and app
                  availability is managed per app and user/group instead. App IDs are not resolved to names because the module
                  has no app catalog cmdlet; look them up under Manage apps. User counts cover direct assignments only.
.LINK
    https://learn.microsoft.com/powershell/module/microsoftteams/get-csteamsapppermissionpolicy
.LINK
    https://learn.microsoft.com/microsoftteams/app-centric-management
#>
#Requires -Version 5.1
#Requires -Modules MicrosoftTeams

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$IncludeUserCounts,

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'

#region Helpers
function Connect-TeamsIfNeeded {
    <# Connects to Microsoft Teams PowerShell only when there is no live session. #>
    [CmdletBinding()]
    param()
    $connected = $false
    try { $null = Get-CsTenant -ErrorAction Stop; $connected = $true } catch { $connected = $false }
    if (-not $connected) {
        Write-Verbose 'Connecting to Microsoft Teams PowerShell.'
        Connect-MicrosoftTeams -ErrorAction Stop | Out-Null
    }
}

function Get-PolicyName {
    <# Normalises a policy identity or Get-CsOnlineUser policy value ("Tag:Name", UserPolicyDefinition object or $null) to its name; empty = Global. #>
    param([Parameter()][object]$Value)
    $name = [string]$Value
    if ($null -ne $Value -and $null -ne $Value.PSObject.Properties['Name']) { $name = [string]$Value.Name }
    $name = $name -replace '^Tag:', ''
    if ([string]::IsNullOrWhiteSpace($name)) { return 'Global' }
    return $name
}

function Get-AppIdList {
    <# Joins the Id values of an app list (DefaultCatalogApps, PinnedAppBarApps ...) and appends the Order when present. #>
    param([Parameter()][object[]]$Apps)
    $items = foreach ($app in @($Apps)) {
        if ($null -ne $app.PSObject.Properties['Order']) { '{0}:{1}' -f $app.Order, $app.Id } else { [string]$app.Id }
    }
    return (@($items) -join ';')
}

function Format-NameList {
    <# Joins names for the console summary; an empty list reads as "none". #>
    param([Parameter()][string[]]$Names)
    if (@($Names).Count -eq 0) { return 'none' }
    return (@($Names) -join ', ')
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('TeamsAppPolicies_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$setupPath = [System.IO.Path]::ChangeExtension($OutputPath, $null) + '_SetupPolicies.csv'

try { Connect-TeamsIfNeeded } catch { throw "Failed to connect to Microsoft Teams PowerShell: $($_.Exception.Message)" }

try {
    $permissionPolicies = @(Get-CsTeamsAppPermissionPolicy -ErrorAction Stop)
    $setupPolicies = @(Get-CsTeamsAppSetupPolicy -ErrorAction Stop)
}
catch {
    throw "Failed to read the Teams app policies: $($_.Exception.Message)"
}
$customAppsEnabled = $null
try { $customAppsEnabled = (Get-CsTeamsSettingsCustomApp -ErrorAction Stop).IsSideloadedAppsInteractionEnabled }
catch { Write-Warning "Could not read the org-wide custom app setting: $($_.Exception.Message)" }

$permissionCounts = @{}
$setupCounts = @{}
if ($IncludeUserCounts) {
    Write-Progress -Activity 'Counting users per app policy' -Status 'Enumerating users with Get-CsOnlineUser'
    try { $users = @(Get-CsOnlineUser -ResultSize Unlimited -ErrorAction Stop) } catch { throw "Failed to enumerate users: $($_.Exception.Message)" }
    foreach ($user in $users) {
        $permissionName = Get-PolicyName -Value $user.TeamsAppPermissionPolicy
        $setupName = Get-PolicyName -Value $user.TeamsAppSetupPolicy
        $permissionCounts[$permissionName] = [int]$permissionCounts[$permissionName] + 1
        $setupCounts[$setupName] = [int]$setupCounts[$setupName] + 1
    }
    Write-Progress -Activity 'Counting users per app policy' -Completed
    Write-Verbose "Counted $($users.Count) users."
}

$permissionRows = foreach ($policy in $permissionPolicies) {
    $name = Get-PolicyName -Value $policy.Identity
    $flags = New-Object -TypeName System.Collections.Generic.List[string]
    # A catalog in BlockedAppList mode with an empty list blocks nothing, i.e. every app of that catalog is allowed.
    if ([string]$policy.GlobalCatalogAppsType -eq 'BlockedAppList' -and @($policy.GlobalCatalogApps).Count -eq 0) { $flags.Add('AllowsAllThirdPartyApps') }
    if ([string]$policy.PrivateCatalogAppsType -eq 'BlockedAppList' -and @($policy.PrivateCatalogApps).Count -eq 0) { $flags.Add('AllowsAllCustomApps') }
    [PSCustomObject]@{
        PolicyKind             = 'AppPermissionPolicy'
        PolicyName             = $name
        Description            = $policy.Description
        DefaultCatalogAppsType = [string]$policy.DefaultCatalogAppsType
        DefaultCatalogAppCount = @($policy.DefaultCatalogApps).Count
        DefaultCatalogAppIds   = Get-AppIdList -Apps $policy.DefaultCatalogApps
        GlobalCatalogAppsType  = [string]$policy.GlobalCatalogAppsType
        GlobalCatalogAppCount  = @($policy.GlobalCatalogApps).Count
        GlobalCatalogAppIds    = Get-AppIdList -Apps $policy.GlobalCatalogApps
        PrivateCatalogAppsType = [string]$policy.PrivateCatalogAppsType
        PrivateCatalogAppCount = @($policy.PrivateCatalogApps).Count
        PrivateCatalogAppIds   = Get-AppIdList -Apps $policy.PrivateCatalogApps
        UserCount              = $(if ($IncludeUserCounts) { [int]$permissionCounts[$name] } else { $null })
        Flags                  = ($flags -join ';')
    }
}
$setupRows = foreach ($policy in $setupPolicies) {
    $name = Get-PolicyName -Value $policy.Identity
    $flags = New-Object -TypeName System.Collections.Generic.List[string]
    if ($policy.AllowSideLoading -eq $true) { $flags.Add('AllowsSideloading') }
    [PSCustomObject]@{
        PolicyKind              = 'AppSetupPolicy'
        PolicyName              = $name
        Description             = $policy.Description
        AllowUserPinning        = $policy.AllowUserPinning
        AllowSideLoading        = $policy.AllowSideLoading
        PinnedAppBarAppCount    = @($policy.PinnedAppBarApps).Count
        PinnedAppBarApps        = Get-AppIdList -Apps $policy.PinnedAppBarApps
        PinnedMessageBarApps    = Get-AppIdList -Apps $policy.PinnedMessageBarApps
        InstalledAppCount       = @($policy.AppPresetList).Count
        InstalledApps           = Get-AppIdList -Apps $policy.AppPresetList
        UserCount               = $(if ($IncludeUserCounts) { [int]$setupCounts[$name] } else { $null })
        Flags                   = ($flags -join ';')
    }
}
$permissionRows = @($permissionRows | Sort-Object -Property PolicyName)
$setupRows = @($setupRows | Sort-Object -Property PolicyName)
if ($permissionRows.Count -gt 0) { $permissionRows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
if ($setupRows.Count -gt 0) { $setupRows | Export-Csv -Path $setupPath -NoTypeInformation -Encoding UTF8 }

$customAppsText = 'unknown'
if ($null -ne $customAppsEnabled) { $customAppsText = [string]$customAppsEnabled }
Write-Host ''
Write-Host 'Teams app policies summary' -ForegroundColor Cyan
Write-Host ('  App permission policies / app setup policies : {0} / {1}' -f $permissionRows.Count, $setupRows.Count)
Write-Host ('  Org-wide custom apps interaction enabled     : {0}' -f $customAppsText)
$sideloading = @($setupRows | Where-Object { $_.Flags -like '*AllowsSideloading*' } | ForEach-Object { $_.PolicyName })
$allThirdParty = @($permissionRows | Where-Object { $_.Flags -like '*AllowsAllThirdPartyApps*' } | ForEach-Object { $_.PolicyName })
Write-Host ('  Setup policies allowing custom app upload    : {0}' -f (Format-NameList -Names $sideloading)) -ForegroundColor Yellow
Write-Host ('  Permission policies allowing all 3rd-party   : {0}' -f (Format-NameList -Names $allThirdParty)) -ForegroundColor Yellow
if ($IncludeUserCounts) {
    Write-Host '  Users per app permission policy (direct assignments):'
    foreach ($row in @($permissionRows | Sort-Object -Property UserCount -Descending)) { Write-Host ('    {0,-45} {1,6}' -f $row.PolicyName, $row.UserCount) }
}
Write-Host '  Note: tenants on app centric management manage availability per app; permission policies are then legacy and read-only.' -ForegroundColor Gray
Write-Host ('  Files                                        : {0}, {1}' -f $OutputPath, $setupPath)

if ($PassThru) { $permissionRows; $setupRows }
#endregion Main
