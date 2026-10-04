<#
.SYNOPSIS
    Reports the SharePoint Online sites in the tenant recycle bin with their remaining retention, and optionally restores or purges them.
.DESCRIPTION
    Reads Get-SPODeletedSite -Limit All (optionally including or limited to OneDrive personal sites) and shapes one row per
    deleted site with URL, site ID, status, deletion time, days remaining in the 93-day retention, expected purge date, quota
    and an IsOneDrive flag. -SiteUrl narrows the report to specific sites. With -Restore the listed sites are restored with
    Restore-SPODeletedSite; with -PermanentlyDelete they are purged with Remove-SPODeletedSite. Both honour -WhatIf / -Confirm
    and the outcome is written to the Action column of the CSV.
.PARAMETER TenantName
    Tenant name prefix, for example contoso for https://contoso-admin.sharepoint.com.
.PARAMETER IncludeOneDrive
    Also list deleted OneDrive personal sites (Get-SPODeletedSite -IncludePersonalSite).
.PARAMETER OnlyOneDrive
    List only deleted OneDrive personal sites (Get-SPODeletedSite -IncludeOnlyPersonalSite).
.PARAMETER SiteUrl
    Restrict the report, the restore or the purge to these deleted site URLs.
.PARAMETER Restore
    Restore the sites given in -SiteUrl from the recycle bin.
.PARAMETER PermanentlyDelete
    Permanently delete the sites given in -SiteUrl from the recycle bin. This cannot be undone.
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\SPODeletedSites_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-SPODeletedSitesReport.ps1 -TenantName contoso -IncludeOneDrive
    Exports every deleted site and OneDrive with the days left before it is purged automatically.
.EXAMPLE
    PS> .\Get-SPODeletedSitesReport.ps1 -TenantName contoso -Restore -SiteUrl https://contoso.sharepoint.com/sites/Finance
    Restores the Finance site after confirmation; use -WhatIf first to preview.
.EXAMPLE
    PS> .\Get-SPODeletedSitesReport.ps1 -TenantName contoso -PermanentlyDelete -SiteUrl $urlsToPurge -Confirm:$false
    Purges the listed sites without prompting, for example to reuse their URLs immediately.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x on Windows, Microsoft.Online.SharePoint.PowerShell
    Permissions : SharePoint Administrator role; Global Reader is sufficient for the report. Restore and purge need SharePoint Administrator.
    Category    : SharePoint administration (SPO module)
    Changes     : Optional (-Restore / -PermanentlyDelete)
    Notes       : The SharePoint Online Management Shell runs on Windows only. Deleted sites are kept for 93 days. A site that
                  belonged to a Microsoft 365 group should be restored by restoring the group (Entra admin center > Groups >
                  Deleted groups, or Graph POST /directory/deletedItems/{id}/restore) within its 30-day window; restoring only
                  the site leaves it disconnected from the group. Purged sites cannot be recovered by Microsoft support.
.LINK
    https://learn.microsoft.com/powershell/module/sharepoint-online/get-spodeletedsite
.LINK
    https://learn.microsoft.com/powershell/module/sharepoint-online/restore-spodeletedsite
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Online.SharePoint.PowerShell

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$TenantName,

    [Parameter()]
    [switch]$IncludeOneDrive,

    [Parameter()]
    [switch]$OnlyOneDrive,

    [Parameter()]
    [string[]]$SiteUrl,

    [Parameter()]
    [switch]$Restore,

    [Parameter()]
    [switch]$PermanentlyDelete,

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
if ($Restore -and $PermanentlyDelete) { throw 'Use either -Restore or -PermanentlyDelete, not both.' }
if (($Restore -or $PermanentlyDelete) -and ($null -eq $SiteUrl -or $SiteUrl.Count -eq 0)) { throw '-Restore and -PermanentlyDelete require -SiteUrl.' }

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('SPODeletedSites_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try {
    Connect-SpoIfNeeded -AdminUrl "https://$TenantName-admin.sharepoint.com"
}
catch {
    throw "Failed to connect to the SharePoint Online admin center: $($_.Exception.Message)"
}

$queryParams = @{ Limit = 'All'; ErrorAction = 'Stop' }
if ($OnlyOneDrive) { $queryParams['IncludeOnlyPersonalSite'] = $true } elseif ($IncludeOneDrive) { $queryParams['IncludePersonalSite'] = $true }
try {
    $deletedSites = @(Get-SPODeletedSite @queryParams)
}
catch {
    throw "Failed to read the tenant recycle bin: $($_.Exception.Message)"
}
Write-Verbose "Found $($deletedSites.Count) deleted sites."
if ($null -ne $SiteUrl -and $SiteUrl.Count -gt 0) {
    $wanted = @($SiteUrl | ForEach-Object { $_.TrimEnd('/') })
    $deletedSites = @($deletedSites | Where-Object { $wanted -contains $_.Url.TrimEnd('/') })
    foreach ($url in $wanted) { if (@($deletedSites | Where-Object { $_.Url.TrimEnd('/') -eq $url }).Count -eq 0) { Write-Warning "$url is not in the recycle bin." } }
}

# Actions run before the rows are shaped so the CSV documents the state the site was in and what happened to it.
$actions = @{}
if ($Restore -or $PermanentlyDelete) {
    $verb = if ($Restore) { 'Restore' } else { 'Permanently delete' }
    foreach ($site in $deletedSites) {
        if (-not $PSCmdlet.ShouldProcess($site.Url, "$verb site from the tenant recycle bin")) { continue }
        try {
            if ($Restore) {
                Restore-SPODeletedSite -Identity $site.Url -ErrorAction Stop | Out-Null
                $actions[$site.Url] = 'Restored'
            }
            else {
                Remove-SPODeletedSite -Identity $site.Url -Confirm:$false -ErrorAction Stop | Out-Null
                $actions[$site.Url] = 'PermanentlyDeleted'
            }
        }
        catch {
            $actions[$site.Url] = "Failed: $($_.Exception.Message)"
            Write-Warning "$verb failed for $($site.Url): $($_.Exception.Message)"
        }
    }
    if ($Restore) { Write-Warning 'If a restored site belonged to a Microsoft 365 group, restore the group in Entra ID as well (see .NOTES).' }
}

$records = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($site in $deletedSites) {
    $deletionTime = $site.DeletionTime
    $purgeDate = $null
    if ($null -ne $deletionTime -and $deletionTime -gt [datetime]::MinValue) { $purgeDate = $deletionTime.AddDays(93) }
    $records.Add([PSCustomObject]@{
            Url             = $site.Url
            SiteId          = [string]$site.SiteId
            Status          = [string]$site.Status
            DeletionTime    = $deletionTime
            DaysRemaining   = [int]$site.DaysRemaining
            PurgeDate       = $purgeDate
            StorageQuotaGB  = [math]::Round(([double]$site.StorageQuota) / 1024, 2)
            ResourceQuota   = $site.ResourceQuota
            IsOneDrive      = ($site.Url -like '*-my.sharepoint.com/personal/*')
            Action          = $actions[$site.Url]
        })
}

$output = @($records | Sort-Object -Property DaysRemaining)
if ($output.Count -gt 0) {
    $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
}
else {
    Write-Warning 'No deleted sites matched; no CSV was written.'
}

Write-Host ''
Write-Host 'SharePoint recycle bin summary' -ForegroundColor Cyan
Write-Host ('  Deleted sites            : {0} (OneDrive: {1})' -f $output.Count, @($output | Where-Object { $_.IsOneDrive }).Count)
Write-Host ('  Purged within 7 days     : {0}' -f @($output | Where-Object { $_.DaysRemaining -le 7 }).Count) -ForegroundColor Yellow
$quotaHeldGB = ($output | Measure-Object -Property StorageQuotaGB -Sum).Sum
if ($null -eq $quotaHeldGB) { $quotaHeldGB = 0 }
Write-Host ('  Storage quota held       : {0:N2} GB' -f $quotaHeldGB)
if ($actions.Count -gt 0) {
    foreach ($group in ($output | Where-Object { $null -ne $_.Action } | Group-Object -Property { $_.Action -replace ':.*$' })) {
        Write-Host ('  {0,-25}: {1}' -f $group.Name, $group.Count) -ForegroundColor Yellow
    }
}
Write-Host ('  Rows exported            : {0} -> {1}' -f $output.Count, $OutputPath)

if ($PassThru) { $output }
#endregion Main
