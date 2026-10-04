<#
.SYNOPSIS
    Inventories every OneDrive for Business site with storage, activity and ownership flags, and optionally sets quotas or grants an admin.
.DESCRIPTION
    Reads all personal sites with Get-SPOSite -IncludePersonalSite $true -Limit All -Filter "Url -like '-my.sharepoint.com/personal/'"
    and shapes one row per OneDrive with owner, storage used and quota in GB, percentage used, last content change, status, lock
    state, sharing capability, archive status and flags: OverThreshold (-ThresholdPercent), Dormant (-DaysInactive) and Orphaned
    (no owner, typically a deleted user). With -SetQuota the selected OneDrives get -QuotaGB via Set-SPOSite -StorageQuota; with
    -GrantAdmin the UPN becomes site collection admin via Set-SPOUser. Actions apply to the rows left after -SiteUrl / -OnlyFlagged.
.PARAMETER TenantName
    Tenant name prefix, for example contoso for https://contoso-admin.sharepoint.com.
.PARAMETER ThresholdPercent
    OneDrives using more than this percentage of their quota are flagged OverThreshold. Default 90.
.PARAMETER DaysInactive
    OneDrives with no content change for this many days are flagged Dormant. Default 365.
.PARAMETER SiteUrl
    Only include these OneDrive URLs; wildcards are allowed, for example *personal/j_doe*.
.PARAMETER OnlyFlagged
    Keep only OneDrives with at least one flag.
.PARAMETER SetQuota
    Set the storage quota of the selected OneDrives to -QuotaGB.
.PARAMETER QuotaGB
    New storage quota in GB (1-5120), required with -SetQuota. Set-SPOSite takes MB, the script converts.
.PARAMETER GrantAdmin
    UPN to add as site collection administrator on the selected OneDrives (for example an eDiscovery or offboarding account).
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\SPOOneDriveInventory_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-SPOOneDriveInventory.ps1 -TenantName contoso
    Exports every OneDrive with storage and activity data and prints the total storage, the ten largest and the flag counts.
.EXAMPLE
    PS> .\Get-SPOOneDriveInventory.ps1 -TenantName contoso -ThresholdPercent 95 -OnlyFlagged -SetQuota -QuotaGB 2048 -WhatIf
    Shows which nearly full OneDrives would be raised to 2 TB.
.EXAMPLE
    PS> .\Get-SPOOneDriveInventory.ps1 -TenantName contoso -SiteUrl '*personal/j_doe_contoso_com' -GrantAdmin manager@contoso.com -Confirm:$false
    Makes the manager site collection admin of a leaver's OneDrive so the files can be retrieved.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x on Windows, Microsoft.Online.SharePoint.PowerShell
    Permissions : SharePoint Administrator role; Global Reader is sufficient for the report. Quota and admin changes need SharePoint Administrator.
    Category    : SharePoint administration (SPO module)
    Changes     : Optional (-SetQuota / -GrantAdmin)
    Notes       : The SharePoint Online Management Shell runs on Windows only. Orphaned relies on an empty Owner, which SharePoint
                  sets some time after the account is deleted (the Graph OneDrive usage report's Is Deleted column is authoritative);
                  orphaned OneDrives are kept for OrphanedPersonalSitesRetentionPeriod days. Quotas above 1 TB need a qualifying license.
.LINK
    https://learn.microsoft.com/powershell/module/sharepoint-online/get-sposite
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Online.SharePoint.PowerShell

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$TenantName,

    [Parameter()]
    [ValidateRange(1, 100)]
    [int]$ThresholdPercent = 90,

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$DaysInactive = 365,

    [Parameter()]
    [string[]]$SiteUrl,

    [Parameter()]
    [switch]$OnlyFlagged,

    [Parameter()]
    [switch]$SetQuota,

    [Parameter()]
    [ValidateRange(1, 5120)]
    [int]$QuotaGB,

    [Parameter()]
    [string]$GrantAdmin,

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
#endregion Helpers

#region Main
if ($SetQuota -and -not $PSBoundParameters.ContainsKey('QuotaGB')) { throw '-SetQuota requires -QuotaGB.' }

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('SPOOneDriveInventory_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try {
    Connect-SpoIfNeeded -AdminUrl "https://$TenantName-admin.sharepoint.com"
    $tenant = Get-SPOTenant -ErrorAction Stop
    $drives = @(Get-SPOSite -IncludePersonalSite $true -Limit All -Filter "Url -like '-my.sharepoint.com/personal/'" -ErrorAction Stop)
}
catch {
    throw "Failed to enumerate OneDrive sites: $($_.Exception.Message)"
}

$records = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($drive in $drives) {
    $usedGB = [math]::Round(([double]$drive.StorageUsageCurrent) / 1024, 2)
    $quotaGBValue = [math]::Round(([double]$drive.StorageQuota) / 1024, 2)
    $percentUsed = $null
    if ($drive.StorageQuota -gt 0) { $percentUsed = [math]::Round(([double]$drive.StorageUsageCurrent / [double]$drive.StorageQuota) * 100, 1) }
    $lastModified = $drive.LastContentModifiedDate
    $daysSince = $null
    if ($null -ne $lastModified -and $lastModified -gt [datetime]::MinValue) { $daysSince = [int](((Get-Date) - $lastModified).TotalDays) }
    $flags = @()
    if ($null -ne $percentUsed -and $percentUsed -gt $ThresholdPercent) { $flags += 'OverThreshold' }
    if ($null -ne $daysSince -and $daysSince -gt $DaysInactive) { $flags += 'Dormant' }
    if ([string]::IsNullOrWhiteSpace([string]$drive.Owner)) { $flags += 'Orphaned' }
    $records.Add([PSCustomObject]@{
            Url                     = $drive.Url
            Owner                   = $drive.Owner
            Title                   = $drive.Title
            StorageUsedGB           = $usedGB
            StorageQuotaGB          = $quotaGBValue
            PercentUsed             = $percentUsed
            LastContentModifiedDate = $lastModified
            DaysSinceModified       = $daysSince
            Status                  = [string]$drive.Status
            LockState               = [string]$drive.LockState
            SharingCapability       = [string]$drive.SharingCapability
            ArchiveStatus           = [string]$drive.ArchiveStatus
            IsOverThreshold         = ($flags -contains 'OverThreshold')
            IsDormant               = ($flags -contains 'Dormant')
            IsOrphaned              = ($flags -contains 'Orphaned')
            Flags                   = ($flags -join '; ')
            Action                  = $null
        })
}

$output = @($records)
if ($null -ne $SiteUrl -and $SiteUrl.Count -gt 0) {
    $output = @($output | Where-Object { $url = $_.Url; @($SiteUrl | Where-Object { $url -like $_ -or $url.TrimEnd('/') -eq $_.TrimEnd('/') }).Count -gt 0 })
}
if ($OnlyFlagged) { $output = @($output | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Flags) }) }
$output = @($output | Sort-Object -Property StorageUsedGB -Descending)

if ($SetQuota -or -not [string]::IsNullOrWhiteSpace($GrantAdmin)) {
    $counter = 0
    foreach ($row in $output) {
        $counter++
        Write-Progress -Activity 'Changing OneDrive sites' -Status "$counter of $($output.Count): $($row.Url)" -PercentComplete ([int](($counter / $output.Count) * 100))
        $actions = @()
        try {
            if ($SetQuota -and $PSCmdlet.ShouldProcess($row.Url, "Set storage quota to $QuotaGB GB")) {
                Set-SPOSite -Identity $row.Url -StorageQuota ($QuotaGB * 1024) -ErrorAction Stop | Out-Null
                $actions += "QuotaSet:$QuotaGB"
            }
            if (-not [string]::IsNullOrWhiteSpace($GrantAdmin) -and $PSCmdlet.ShouldProcess($row.Url, "Grant site collection admin to $GrantAdmin")) {
                Set-SPOUser -Site $row.Url -LoginName $GrantAdmin -IsSiteCollectionAdmin $true -ErrorAction Stop | Out-Null
                $actions += "AdminGranted:$GrantAdmin"
            }
        }
        catch {
            $actions += "Failed: $($_.Exception.Message)"
            Write-Warning "$($row.Url): $($_.Exception.Message)"
        }
        $row.Action = $actions -join '; '
    }
    Write-Progress -Activity 'Changing OneDrive sites' -Completed
}

if ($output.Count -gt 0) { $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No OneDrive sites matched the selected filters; no CSV was written.' }

$totalGB = [double]($records | Measure-Object -Property StorageUsedGB -Sum).Sum
Write-Host ''
Write-Host 'OneDrive inventory summary' -ForegroundColor Cyan
Write-Host ('  OneDrive sites            : {0} (total storage {1:N2} GB)' -f $records.Count, $totalGB)
Write-Host ('  Over {0,3}% of quota         : {1}' -f $ThresholdPercent, @($records | Where-Object { $_.IsOverThreshold }).Count) -ForegroundColor Yellow
Write-Host ('  Dormant (> {0} days)      : {1}' -f $DaysInactive, @($records | Where-Object { $_.IsDormant }).Count)
$orphanedCount = @($records | Where-Object { $_.IsOrphaned }).Count
Write-Host ('  Orphaned (no owner)       : {0} (retained {1} days after deletion)' -f $orphanedCount, $tenant.OrphanedPersonalSitesRetentionPeriod) -ForegroundColor Yellow
Write-Host '  Top 10 by storage:'
foreach ($row in ($records | Sort-Object -Property StorageUsedGB -Descending | Select-Object -First 10)) { Write-Host ('    {0,10:N2} GB  {1}' -f $row.StorageUsedGB, $row.Url) }
$changedCount = @($output | Where-Object { $_.Action -match 'QuotaSet|AdminGranted' }).Count
if ($changedCount -gt 0) { Write-Host ('  Sites changed             : {0}' -f $changedCount) -ForegroundColor Yellow }
Write-Host ('  Rows exported             : {0} -> {1}' -f $output.Count, $OutputPath)

if ($PassThru) { $output }
#endregion Main
