<#
.SYNOPSIS
    Finds SharePoint Online sites without a valid owner, locked sites and dormant sites, and optionally assigns a new owner.
.DESCRIPTION
    Enumerates site collections with Get-SPOSite -Limit All and evaluates each one: empty Owner (NoOwner), an owner that no
    longer resolves on the site with Get-SPOUser -Site -LoginName (OwnerNotResolved, typically a deleted account), a LockState
    other than Unlock (Locked) and no content change for -DaysInactive days (Dormant). Group-connected and Teams channel sites
    are owned by their Microsoft 365 group (OwnerType = Microsoft365Group) and skip the owner check. With -SetOwner the
    orphaned non-group sites get the given UPN as primary owner via Set-SPOSite -Owner (honours -WhatIf / -Confirm).
.PARAMETER TenantName
    Tenant name prefix, for example contoso for https://contoso-admin.sharepoint.com.
.PARAMETER DaysInactive
    Sites with no content change for this many days are flagged Dormant. Default 365.
.PARAMETER SkipOwnerCheck
    Do not resolve the owner on each site (saves one Get-SPOUser call per site; only NoOwner, Locked and Dormant are evaluated).
.PARAMETER OnlyFindings
    Export only sites with at least one finding.
.PARAMETER SetOwner
    UPN to set as primary owner on every orphaned site that is not group-connected.
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\SPOOrphanedSites_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-SPOOrphanedSites.ps1 -TenantName contoso
    Evaluates every site and prints how many are orphaned, locked or dormant.
.EXAMPLE
    PS> .\Get-SPOOrphanedSites.ps1 -TenantName contoso -OnlyFindings -DaysInactive 180 -PassThru | Where-Object { $_.IsOrphaned }
    Exports only sites with findings and returns the orphaned ones for follow-up.
.EXAMPLE
    PS> .\Get-SPOOrphanedSites.ps1 -TenantName contoso -SetOwner spo.admin@contoso.com -WhatIf
    Shows which orphaned sites would receive the new owner.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x on Windows, Microsoft.Online.SharePoint.PowerShell
    Permissions : SharePoint Administrator role (the owner check reads the site user list); Global Reader works with -SkipOwnerCheck.
    Category    : SharePoint administration (SPO module)
    Changes     : Optional (-SetOwner)
    Notes       : The SharePoint Online Management Shell runs on Windows only. The owner check costs one call per site. A deleted
                  account can linger in a site's user information list for a while, so OwnerNotResolved may lag the deletion;
                  for a definitive answer compare the Owner column with Entra ID. Ownerless Microsoft 365 groups are not
                  detected here - their owners live in Entra ID (see the EntraID folder). OneDrive and redirect sites are skipped.
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
    [ValidateRange(1, 3650)]
    [int]$DaysInactive = 365,

    [Parameter()]
    [switch]$SkipOwnerCheck,

    [Parameter()]
    [switch]$OnlyFindings,

    [Parameter()]
    [string]$SetOwner,

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [switch]$PassThru
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

function ConvertTo-TemplateName {
    <# Maps a site template id to the name shown in the SharePoint admin center; unknown ids are returned unchanged. #>
    param(
        [Parameter()]
        [AllowEmptyString()]
        [string]$Template
    )
    $names = @{
        'GROUP#0' = 'Team site (Microsoft 365 group)'; 'STS#3' = 'Team site (no group)'; 'STS#0' = 'Classic team site'
        'SITEPAGEPUBLISHING#0' = 'Communication site'; 'TEAMCHANNEL#0' = 'Teams private channel site'; 'TEAMCHANNEL#1' = 'Teams shared channel site'
        'SPSPERS#10' = 'OneDrive'; 'SPSMSITEHOST#0' = 'OneDrive host'; 'APPCATALOG#0' = 'App catalog'; 'SRCHCEN#0' = 'Search center'
        'POINTPUBLISHINGHUB#0' = 'PointPublishing hub'; 'POINTPUBLISHINGTOPIC#0' = 'PointPublishing topic'; 'EHS#1' = 'Classic team site (SPO configuration)'
        'REDIRECTSITE#0' = 'Redirect site'; 'BLANKINTERNET#0' = 'Classic publishing site'
    }
    if ($names.ContainsKey($Template)) { return $names[$Template] }
    return $Template
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('SPOOrphanedSites_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try {
    Connect-SpoIfNeeded -AdminUrl "https://$TenantName-admin.sharepoint.com"
    $sites = @(Get-SPOSite -Limit All -ErrorAction Stop | Where-Object { $_.Template -ne 'REDIRECTSITE#0' })
}
catch {
    throw "Failed to enumerate site collections: $($_.Exception.Message)"
}
Write-Verbose "Evaluating $($sites.Count) site collections."

$dormantBefore = (Get-Date).AddDays(-$DaysInactive)
$records = New-Object -TypeName System.Collections.Generic.List[object]
$counter = 0
foreach ($site in $sites) {
    $counter++
    Write-Progress -Activity 'Evaluating site ownership' -Status "$counter of $($sites.Count): $($site.Url)" -PercentComplete ([int](($counter / $sites.Count) * 100))
    $owner = [string]$site.Owner
    $groupId = [string]$site.GroupId
    $isGroupOwned = ([string]$site.Template -like 'GROUP#*') -or ([string]$site.Template -like 'TEAMCHANNEL#*') -or ($groupId -ne '' -and $groupId -ne [guid]::Empty.ToString())
    $lockState = [string]$site.LockState
    $findings = @()
    $detail = $null
    if ([string]::IsNullOrWhiteSpace($owner)) { $findings += 'NoOwner' }
    elseif (-not $isGroupOwned -and -not $SkipOwnerCheck -and $lockState -eq 'Unlock') {
        try {
            $null = Get-SPOUser -Site $site.Url -LoginName $owner -ErrorAction Stop
        }
        catch {
            $findings += 'OwnerNotResolved'
            $detail = $_.Exception.Message
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($lockState) -and $lockState -ne 'Unlock') { $findings += "Locked:$lockState" }
    $lastModified = $site.LastContentModifiedDate
    if ($null -ne $lastModified -and $lastModified -gt [datetime]::MinValue -and $lastModified -lt $dormantBefore) { $findings += 'Dormant' }
    $isOrphaned = ($findings -contains 'NoOwner') -or ($findings -contains 'OwnerNotResolved')
    $ownerType = 'User'
    if ($isGroupOwned) { $ownerType = 'Microsoft365Group' } elseif ([string]::IsNullOrWhiteSpace($owner)) { $ownerType = 'None' }

    $result = $null
    if ($isOrphaned -and -not [string]::IsNullOrWhiteSpace($SetOwner)) {
        $result = 'SkippedByUser'
        if ($isGroupOwned) { $result = 'Skipped: group-connected, manage owners in Entra ID' }
        elseif ($PSCmdlet.ShouldProcess($site.Url, "Set primary owner to $SetOwner")) {
            try {
                Set-SPOSite -Identity $site.Url -Owner $SetOwner -ErrorAction Stop | Out-Null
                $result = 'OwnerSet'
            }
            catch {
                $result = "Failed: $($_.Exception.Message)"
                Write-Warning "Could not set the owner of $($site.Url): $($_.Exception.Message)"
            }
        }
    }
    $records.Add([PSCustomObject]@{
            Url                     = $site.Url
            Title                   = $site.Title
            Template                = ConvertTo-TemplateName -Template ([string]$site.Template)
            TemplateId              = $site.Template
            Owner                   = $owner
            OwnerType               = $ownerType
            IsOrphaned              = $isOrphaned
            Findings                = ($findings -join '; ')
            Detail                  = $detail
            LockState               = $lockState
            LastContentModifiedDate = $lastModified
            StorageUsedGB           = [math]::Round(([double]$site.StorageUsageCurrent) / 1024, 2)
            Action                  = $result
        })
}
Write-Progress -Activity 'Evaluating site ownership' -Completed

$output = @($records)
if ($OnlyFindings) { $output = @($output | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Findings) }) }
$output = @($output | Sort-Object -Property @{ Expression = 'IsOrphaned'; Descending = $true }, Url)
if ($output.Count -gt 0) {
    $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
}
else {
    Write-Warning 'No sites matched the selected filters; no CSV was written.'
}

Write-Host ''
Write-Host 'SharePoint orphaned sites summary' -ForegroundColor Cyan
Write-Host ('  Sites evaluated           : {0} (owner check: {1})' -f $records.Count, (-not $SkipOwnerCheck.IsPresent))
Write-Host ('  Orphaned (no valid owner) : {0}' -f @($records | Where-Object { $_.IsOrphaned }).Count) -ForegroundColor Yellow
Write-Host ('  Locked                    : {0}' -f @($records | Where-Object { $_.Findings -like '*Locked*' }).Count)
Write-Host ('  Dormant (> {0} days)      : {1}' -f $DaysInactive, @($records | Where-Object { $_.Findings -like '*Dormant*' }).Count)
Write-Host ('  Group-owned sites         : {0}' -f @($records | Where-Object { $_.OwnerType -eq 'Microsoft365Group' }).Count)
if (-not [string]::IsNullOrWhiteSpace($SetOwner)) { Write-Host ('  Owner set to {0}: {1}' -f $SetOwner, @($records | Where-Object { $_.Action -eq 'OwnerSet' }).Count) -ForegroundColor Yellow }
Write-Host ('  Rows exported             : {0} -> {1}' -f $output.Count, $OutputPath)

if ($PassThru) { $output }
#endregion Main
