<#
.SYNOPSIS
    Sets the external sharing capability, default link settings and domain restrictions on selected SharePoint Online sites.
.DESCRIPTION
    Builds a target list from -SiteUrl, a CSV (-InputCsv: Url column plus an optional per-row SharingCapability column) or
    every site of a template (-Template, for example GROUP#0 for all group-connected sites), reads each site with Get-SPOSite
    -Identity -Detailed and compares the requested settings with the current values. Compliant sites are skipped; the others
    are changed with Set-SPOSite only when -Apply is present (each change honours -WhatIf / -Confirm). Writes a results CSV.
.PARAMETER TenantName
    Tenant name prefix, for example contoso for https://contoso-admin.sharepoint.com.
.PARAMETER SiteUrl
    One or more site collection URLs to change.
.PARAMETER InputCsv
    CSV with a Url column and an optional SharingCapability column that overrides -SharingCapability per row.
.PARAMETER Template
    Change every site of this template, for example GROUP#0 (group-connected team sites) or SITEPAGEPUBLISHING#0 (communication sites).
.PARAMETER SharingCapability
    Target sharing capability: Disabled, ExistingExternalUserSharingOnly, ExternalUserSharingOnly or ExternalUserAndGuestSharing (Anyone).
.PARAMETER DefaultSharingLinkType
    Default type of new sharing links: None, Direct (specific people), Internal (people in the organization) or AnonymousAccess.
.PARAMETER DefaultLinkPermission
    Default permission of new sharing links: None, View or Edit.
.PARAMETER SharingDomainRestrictionMode
    None, AllowList or BlockList. AllowList requires -SharingAllowedDomainList.
.PARAMETER SharingAllowedDomainList
    Domains allowed for external sharing when the restriction mode is AllowList, for example fabrikam.com, northwind.com.
.PARAMETER Apply
    Perform the changes. Without this switch the script only reports what would change.
.PARAMETER OutputPath
    Path of the results CSV. Defaults to .\Reports\SPOSiteSharingChanges_<timestamp>.csv.
.EXAMPLE
    PS> .\Set-SPOSiteSharing.ps1 -TenantName contoso -Template GROUP#0 -SharingCapability ExternalUserSharingOnly
    Shows which group-connected sites would move to "New and existing guests" without changing anything.
.EXAMPLE
    PS> .\Set-SPOSiteSharing.ps1 -TenantName contoso -InputCsv .\sites.csv -SharingCapability Disabled -DefaultLinkPermission View -Apply -Confirm:$false
    Disables external sharing (or applies the per-row SharingCapability from the CSV) and defaults new links to View on every listed site.
.EXAMPLE
    PS> .\Set-SPOSiteSharing.ps1 -TenantName contoso -SiteUrl $url -SharingDomainRestrictionMode AllowList -SharingAllowedDomainList fabrikam.com -Apply -WhatIf
    Previews restricting external sharing of the site in $url to one partner domain.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x on Windows, Microsoft.Online.SharePoint.PowerShell
    Permissions : SharePoint Administrator role.
    Category    : SharePoint administration (SPO module)
    Changes     : Yes
    Notes       : The SharePoint Online Management Shell runs on Windows only. A site cannot be more permissive than the tenant;
                  such requests are reported as Failed - raise the tenant first with Set-SPOTenant -SharingCapability. For group-
                  connected sites this changes SharePoint sharing only (group guest membership is an Entra ID setting). Lowering a
                  level cuts existing external access immediately.
.LINK
    https://learn.microsoft.com/powershell/module/sharepoint-online/set-sposite
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Online.SharePoint.PowerShell

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$TenantName,

    [Parameter()]
    [string[]]$SiteUrl,

    [Parameter()]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$InputCsv,

    [Parameter()]
    [string]$Template,

    [Parameter()]
    [ValidateSet('Disabled', 'ExistingExternalUserSharingOnly', 'ExternalUserSharingOnly', 'ExternalUserAndGuestSharing')]
    [string]$SharingCapability,

    [Parameter()]
    [ValidateSet('None', 'Direct', 'Internal', 'AnonymousAccess')]
    [string]$DefaultSharingLinkType,

    [Parameter()]
    [ValidateSet('None', 'View', 'Edit')]
    [string]$DefaultLinkPermission,

    [Parameter()]
    [ValidateSet('None', 'AllowList', 'BlockList')]
    [string]$SharingDomainRestrictionMode,

    [Parameter()]
    [string[]]$SharingAllowedDomainList,

    [Parameter()]
    [switch]$Apply,

    [Parameter()]
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'

#region Helpers
function Connect-SpoIfNeeded {
    <# Connects to the SharePoint Online admin endpoint only when no live session exists. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AdminUrl
    )
    $connected = $false
    try { $null = Get-SPOTenant -ErrorAction Stop; $connected = $true } catch { $connected = $false }
    if (-not $connected) {
        Write-Verbose "Connecting to SharePoint Online admin center $AdminUrl."
        Connect-SPOService -Url $AdminUrl -ErrorAction Stop
    }
}
#endregion Helpers

#region Main
if (@('SiteUrl', 'InputCsv', 'Template' | Where-Object { $PSBoundParameters.ContainsKey($_) }).Count -eq 0) { throw 'Specify the target sites with -SiteUrl, -InputCsv or -Template.' }

# Requested settings keyed by Set-SPOSite parameter name; a per-row CSV value can override SharingCapability later.
$desired = [ordered]@{}
if ($PSBoundParameters.ContainsKey('SharingCapability')) { $desired['SharingCapability'] = $SharingCapability }
if ($PSBoundParameters.ContainsKey('DefaultSharingLinkType')) { $desired['DefaultSharingLinkType'] = $DefaultSharingLinkType }
if ($PSBoundParameters.ContainsKey('DefaultLinkPermission')) { $desired['DefaultLinkPermission'] = $DefaultLinkPermission }
if ($PSBoundParameters.ContainsKey('SharingDomainRestrictionMode')) { $desired['SharingDomainRestrictionMode'] = $SharingDomainRestrictionMode }
if ($PSBoundParameters.ContainsKey('SharingAllowedDomainList')) { $desired['SharingAllowedDomainList'] = ($SharingAllowedDomainList -join ' ') }
if ($desired.Count -eq 0 -and -not $PSBoundParameters.ContainsKey('InputCsv')) { throw 'Specify at least one setting to change, for example -SharingCapability.' }

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('SPOSiteSharingChanges_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try {
    Connect-SpoIfNeeded -AdminUrl "https://$TenantName-admin.sharepoint.com"
    $tenantSharing = [string](Get-SPOTenant -ErrorAction Stop).SharingCapability
}
catch {
    throw "Failed to connect to the SharePoint Online admin center: $($_.Exception.Message)"
}
$sharingRank = @{ Disabled = 0; ExistingExternalUserSharingOnly = 1; ExternalUserSharingOnly = 2; ExternalUserAndGuestSharing = 3 }
Write-Verbose "Tenant sharing level $tenantSharing; requested settings: $(@($desired.Keys) -join ', ')."
$targets = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($url in @($SiteUrl)) { if (-not [string]::IsNullOrWhiteSpace($url)) { $targets.Add([PSCustomObject]@{ Url = $url.TrimEnd('/'); SharingCapability = $SharingCapability }) } }
if ($PSBoundParameters.ContainsKey('InputCsv')) {
    foreach ($row in @(Import-Csv -Path $InputCsv)) {
        if ($null -eq $row.PSObject.Properties['Url']) { throw "The CSV '$InputCsv' needs a Url column (optional: SharingCapability)." }
        $rowCapability = $SharingCapability
        if ($null -ne $row.PSObject.Properties['SharingCapability'] -and -not [string]::IsNullOrWhiteSpace($row.SharingCapability)) { $rowCapability = $row.SharingCapability.Trim() }
        $targets.Add([PSCustomObject]@{ Url = ([string]$row.Url).TrimEnd('/'); SharingCapability = $rowCapability })
    }
}
if ($PSBoundParameters.ContainsKey('Template')) {
    try { $templateSites = @(Get-SPOSite -Limit All -Template $Template -ErrorAction Stop) } catch { throw "Failed to enumerate sites of template ${Template}: $($_.Exception.Message)" }
    foreach ($site in $templateSites) { $targets.Add([PSCustomObject]@{ Url = $site.Url; SharingCapability = $SharingCapability }) }
}

$results = New-Object -TypeName System.Collections.Generic.List[object]
$counter = 0
foreach ($target in $targets) {
    $counter++
    Write-Progress -Activity 'Applying sharing settings' -Status "$counter of $($targets.Count): $($target.Url)" -PercentComplete ([int](($counter / $targets.Count) * 100))
    $settings = [ordered]@{}
    foreach ($key in $desired.Keys) { $settings[$key] = $desired[$key] }
    if (-not [string]::IsNullOrWhiteSpace($target.SharingCapability)) { $settings['SharingCapability'] = $target.SharingCapability }
    $result = [PSCustomObject]@{ Url = $target.Url; Changes = $null; Result = $null; Detail = $null }
    $results.Add($result)
    try {
        if ($settings.Count -eq 0) { $result.Result = 'Skipped'; $result.Detail = 'No setting requested for this site'; continue }
        if ($settings.Contains('SharingCapability')) {
            $wanted = [string]$settings['SharingCapability']
            if (-not $sharingRank.ContainsKey($wanted)) { throw "Invalid SharingCapability value '$wanted'." }
            if ($sharingRank[$wanted] -gt $sharingRank[$tenantSharing]) { throw "SharingCapability '$wanted' is more permissive than the tenant level '$tenantSharing'." }
        }
        $changes = @()
        $current = Get-SPOSite -Identity $target.Url -Detailed -ErrorAction Stop
        foreach ($key in $settings.Keys) {
            $currentValue = $current.$key
            # SharingCapability is the effective (tenant-capped) value; the configured site value is SiteDefinedSharingCapability.
            if ($key -eq 'SharingCapability' -and $null -ne $current.SiteDefinedSharingCapability) { $currentValue = $current.SiteDefinedSharingCapability }
            if ([string]$currentValue -ne [string]$settings[$key]) { $changes += ('{0}: {1} -> {2}' -f $key, $currentValue, $settings[$key]) }
        }
        $result.Changes = $changes -join '; '
        if ($changes.Count -eq 0) { $result.Result = 'AlreadyCompliant'; continue }
        if (-not $Apply) { $result.Result = 'WouldChange'; continue }
        $result.Result = 'SkippedByUser'
        if ($PSCmdlet.ShouldProcess($target.Url, "Set sharing settings ($($result.Changes))")) {
            $setParams = @{}
            foreach ($key in $settings.Keys) { $setParams[$key] = $settings[$key] }
            Set-SPOSite -Identity $target.Url @setParams -ErrorAction Stop | Out-Null
            $result.Result = 'Changed'
        }
    }
    catch {
        $result.Result = 'Failed'
        $result.Detail = $_.Exception.Message
        Write-Warning "$($target.Url): $($_.Exception.Message)"
    }
}
Write-Progress -Activity 'Applying sharing settings' -Completed

$output = @($results)
if ($output.Count -gt 0) { $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }

Write-Host ''
Write-Host 'SharePoint sharing change summary' -ForegroundColor Cyan
Write-Host ('  Mode                 : {0}' -f $(if ($Apply) { 'APPLY' } else { 'Report only (add -Apply to change)' }))
Write-Host ('  Tenant sharing level : {0}' -f $tenantSharing)
foreach ($group in ($output | Group-Object -Property Result | Sort-Object -Property Name)) { Write-Host ('  {0,-21}: {1}' -f $group.Name, $group.Count) }
Write-Host ('  Results exported     : {0} -> {1}' -f $output.Count, $OutputPath)
#endregion Main
