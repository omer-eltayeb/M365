<#
.SYNOPSIS
    Reports every external (guest) user known to SharePoint Online with age, inviter and domain, and optionally removes selected ones.
.DESCRIPTION
    Pages through Get-SPOExternalUser (50 users per call) for the whole tenant or one site (-SiteUrl) and shapes one row per
    external user with display name, e-mail, home domain, invited/accepted identities, inviter, creation date, age in days,
    cross-tenant flag and a stale flag (invited more than -StaleDays ago). Prints the top domains and inviters. With -Remove the
    users listed in -Email are removed from the tenant external user list with Remove-SPOExternalUser (honours -WhatIf/-Confirm).
.PARAMETER TenantName
    Tenant name prefix, for example contoso for https://contoso-admin.sharepoint.com.
.PARAMETER SiteUrl
    Report only the external users of this site collection instead of the whole tenant.
.PARAMETER Filter
    Server-side prefix filter on first name, last name or e-mail (Get-SPOExternalUser -Filter).
.PARAMETER Domain
    Keep only users whose e-mail domain matches this value; wildcards allowed, for example gmail.com or *.fabrikam.com.
.PARAMETER StaleDays
    Users invited more than this many days ago are flagged IsStale. Default 365.
.PARAMETER Remove
    Remove the external users listed in -Email from SharePoint Online (all sites and OneDrives).
.PARAMETER Email
    E-mail addresses of the external users to remove; required with -Remove.
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\SPOExternalUsers_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-SPOExternalUsersReport.ps1 -TenantName contoso
    Exports every external user in the tenant and prints the top guest domains and inviters.
.EXAMPLE
    PS> .\Get-SPOExternalUsersReport.ps1 -TenantName contoso -Domain gmail.com -StaleDays 180 -PassThru | Where-Object { $_.IsStale }
    Lists Gmail guests invited more than 180 days ago.
.EXAMPLE
    PS> .\Get-SPOExternalUsersReport.ps1 -TenantName contoso -Remove -Email 'ex.partner@fabrikam.com' -WhatIf
    Shows the removal that would be performed; drop -WhatIf and confirm to execute it.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x on Windows, Microsoft.Online.SharePoint.PowerShell
    Permissions : SharePoint Administrator role; Global Reader is sufficient for the report. Removal needs SharePoint Administrator.
    Category    : SharePoint administration (SPO module)
    Changes     : Optional (-Remove)
    Notes       : The SharePoint Online Management Shell runs on Windows only. The external user list has no activity data, so
                  IsStale is based on the invitation date; check Entra ID sign-in logs before removing. Remove-SPOExternalUser removes
                  the user from every site (even when the report was scoped with -SiteUrl) but leaves the Entra ID guest account in place.
.LINK
    https://learn.microsoft.com/powershell/module/sharepoint-online/get-spoexternaluser
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Online.SharePoint.PowerShell

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$TenantName,

    [Parameter()]
    [string]$SiteUrl,

    [Parameter()]
    [string]$Filter,

    [Parameter()]
    [string]$Domain,

    [Parameter()]
    [ValidateRange(1, 3650)]
    [int]$StaleDays = 365,

    [Parameter()]
    [switch]$Remove,

    [Parameter()]
    [string[]]$Email,

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
if ($Remove -and ($null -eq $Email -or $Email.Count -eq 0)) { throw 'Specify the external users to remove with -Email when using -Remove.' }

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('SPOExternalUsers_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
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

# Get-SPOExternalUser returns at most 50 users per call; -Position is the zero-based index of the first user of the page.
$pageSize = 50
$queryParams = @{ PageSize = $pageSize; ErrorAction = 'Stop' }
if (-not [string]::IsNullOrWhiteSpace($SiteUrl)) { $queryParams['SiteUrl'] = $SiteUrl }
if (-not [string]::IsNullOrWhiteSpace($Filter)) { $queryParams['Filter'] = $Filter }
$scope = if ([string]::IsNullOrWhiteSpace($SiteUrl)) { 'Tenant' } else { $SiteUrl }
$externalUsers = New-Object -TypeName System.Collections.Generic.List[object]
$position = 0
do {
    Write-Progress -Activity 'Reading external users' -Status "$($externalUsers.Count) users retrieved so far"
    try {
        $page = @(Get-SPOExternalUser -Position $position @queryParams)
    }
    catch {
        throw "Failed to read external users at position ${position}: $($_.Exception.Message)"
    }
    foreach ($user in $page) { $externalUsers.Add($user) }
    $position += $page.Count
} while ($page.Count -eq $pageSize)
Write-Progress -Activity 'Reading external users' -Completed
Write-Verbose "Retrieved $($externalUsers.Count) external users (scope: $scope)."

$records = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($user in $externalUsers) {
    $address = [string]$user.Email
    $userDomain = $null
    if ($address -match '@(.+)$') { $userDomain = $Matches[1].ToLowerInvariant() }
    $created = $user.WhenCreated
    $ageDays = $null
    if ($null -ne $created -and $created -gt [datetime]::MinValue) { $ageDays = [int](((Get-Date) - $created).TotalDays) }
    $records.Add([PSCustomObject]@{
            DisplayName                  = $user.DisplayName
            Email                        = $address
            Domain                       = $userDomain
            InvitedAs                    = $user.InvitedAs
            AcceptedAs                   = $user.AcceptedAs
            AcceptedWithDifferentAccount = ([string]$user.AcceptedAs -ne [string]$user.InvitedAs)
            InvitedBy                    = $user.InvitedBy
            WhenCreated                  = $created
            AgeDays                      = $ageDays
            IsStale                      = ($null -ne $ageDays -and $ageDays -gt $StaleDays)
            IsCrossTenant                = [bool]$user.IsCrossTenant
            LoginName                    = $user.LoginName
            UniqueId                     = $user.UniqueId
            Scope                        = $scope
            Removed                      = $false
        })
}

$output = @($records)
if (-not [string]::IsNullOrWhiteSpace($Domain)) { $output = @($output | Where-Object { $_.Domain -like $Domain }) }
$output = @($output | Sort-Object -Property WhenCreated)

$removedCount = 0
if ($Remove) {
    foreach ($target in $Email) {
        $hits = @($records | Where-Object { $_.Email -eq $target })
        if ($hits.Count -eq 0) { Write-Warning "No external user with e-mail $target was found."; continue }
        foreach ($hit in $hits) {
            if (-not $PSCmdlet.ShouldProcess($hit.Email, 'Remove external user from SharePoint Online (all sites and OneDrives)')) { continue }
            try {
                Remove-SPOExternalUser -UniqueIDs @($hit.UniqueId) -Confirm:$false -ErrorAction Stop | Out-Null
                $hit.Removed = $true
                $removedCount++
            }
            catch {
                Write-Warning "Failed to remove $($hit.Email): $($_.Exception.Message)"
            }
        }
    }
}

if ($output.Count -gt 0) {
    $output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
}
else {
    Write-Warning 'No external users matched the selected filters; no CSV was written.'
}

$staleCount = @($output | Where-Object { $_.IsStale }).Count
Write-Host ''
Write-Host 'SharePoint external users summary' -ForegroundColor Cyan
Write-Host ('  Scope                       : {0}' -f $scope)
Write-Host ('  External users              : {0} (after filters: {1})' -f $records.Count, $output.Count)
Write-Host ('  Invited > {0} days ago       : {1}' -f $StaleDays, $staleCount) -ForegroundColor Yellow
Write-Host '  Top domains:'
foreach ($group in ($output | Group-Object -Property Domain | Sort-Object -Property Count -Descending | Select-Object -First 10)) { Write-Host ('    {0,5}  {1}' -f $group.Count, $group.Name) }
Write-Host '  Top inviters:'
foreach ($group in ($output | Group-Object -Property InvitedBy | Sort-Object -Property Count -Descending | Select-Object -First 5)) { Write-Host ('    {0,5}  {1}' -f $group.Count, $group.Name) }
if ($Remove) { Write-Host ('  Removed                     : {0}' -f $removedCount) -ForegroundColor Yellow }
Write-Host ('  Rows exported               : {0} -> {1}' -f $output.Count, $OutputPath)

if ($PassThru) { $output }
#endregion Main
