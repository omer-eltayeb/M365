<#
.SYNOPSIS
    Exports all SharePoint Online tenant settings to JSON, assesses the key sharing and security settings and diffs against an earlier export.
.DESCRIPTION
    Reads Get-SPOTenant, writes every property to a flat JSON snapshot (-JsonPath) and evaluates the settings that matter for
    external sharing, link defaults, guest expiration, legacy authentication, OneDrive and sync against a recommended value;
    each becomes one CSV row with Setting, Value, Status (Compliant, Review, Info or NotAvailable) and Recommendation. With
    -CompareWith an earlier snapshot is compared property by property and the differences go to a second CSV (drift monitoring).
.PARAMETER TenantName
    Tenant name prefix, for example contoso for https://contoso-admin.sharepoint.com.
.PARAMETER JsonPath
    Path of the JSON snapshot with every Get-SPOTenant property. Defaults to the CSV path with a .json extension.
.PARAMETER CompareWith
    Path of a JSON snapshot written by an earlier run; differences are exported to <OutputPath>_Diff.csv.
.PARAMETER OutputPath
    Path of the assessment CSV. Defaults to .\Reports\SPOTenantSettings_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the assessment objects to the pipeline.
.EXAMPLE
    PS> .\Export-SPOTenantSettings.ps1 -TenantName contoso
    Writes the JSON snapshot and the assessment CSV and prints how many settings need review.
.EXAMPLE
    PS> .\Export-SPOTenantSettings.ps1 -TenantName contoso -CompareWith .\Reports\SPOTenantSettings_20260101-0800.json -Verbose
    Assesses the current settings and lists every tenant property that changed since the January snapshot.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x on Windows, Microsoft.Online.SharePoint.PowerShell
    Permissions : SharePoint Administrator role; Global Reader is sufficient for this read-only export.
    Category    : SharePoint administration (SPO module)
    Changes     : No
    Notes       : The SharePoint Online Management Shell runs on Windows only. Recommendations follow common baseline guidance
                  (Microsoft Secure Score / CIS Microsoft 365 benchmark) and must be weighed against business needs; Review does
                  not mean misconfigured. Settings missing from the installed module version show NotAvailable; storage is in MB.
.LINK
    https://learn.microsoft.com/powershell/module/sharepoint-online/get-spotenant
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Online.SharePoint.PowerShell

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$TenantName,

    [Parameter()]
    [string]$JsonPath,

    [Parameter()]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$CompareWith,

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

function Test-SettingValue {
    <# Evaluates a value against a rule ('A|B' = allowed values, '<=N' / '>=N' = numeric bound, '' = informational). #>
    param(
        [Parameter()]
        [AllowNull()]
        $Value,

        [Parameter()]
        [AllowEmptyString()]
        [string]$Rule
    )
    if ([string]::IsNullOrEmpty($Rule)) { return 'Info' }
    if ($null -eq $Value) { return 'NotAvailable' }
    $text = [string]$Value
    if ($Rule -match '^(<=|>=)(-?\d+)$') {
        $number = 0
        if (-not [int]::TryParse($text, [ref]$number)) { return 'Review' }
        if (($Matches[1] -eq '<=' -and $number -le [int]$Matches[2]) -or ($Matches[1] -eq '>=' -and $number -ge [int]$Matches[2])) { return 'Compliant' }
        return 'Review'
    }
    if (($Rule -split '\|') -contains $text) { return 'Compliant' }
    return 'Review'
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('SPOTenantSettings_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
if ([string]::IsNullOrWhiteSpace($JsonPath)) { $JsonPath = [System.IO.Path]::ChangeExtension($OutputPath, '.json') }

try {
    Connect-SpoIfNeeded -AdminUrl "https://$TenantName-admin.sharepoint.com"
    $tenant = Get-SPOTenant -ErrorAction Stop
}
catch {
    throw "Failed to connect to the SharePoint Online admin center: $($_.Exception.Message)"
}

# Flatten every tenant property to a string so the snapshot is stable across module versions and easy to diff.
$snapshot = [ordered]@{}
foreach ($property in ($tenant.PSObject.Properties | Sort-Object -Property Name)) {
    $value = $property.Value
    if ($value -is [System.Collections.IEnumerable] -and $value -isnot [string]) { $value = (@($value) | ForEach-Object { [string]$_ }) -join ', ' }
    elseif ($null -ne $value) { $value = [string]$value }
    $snapshot[$property.Name] = $value
}
$snapshot | ConvertTo-Json -Depth 2 | Set-Content -Path $JsonPath -Encoding UTF8
Write-Verbose "Wrote $($snapshot.Count) tenant properties to $JsonPath."

# Setting, expected-value rule, recommendation. Rules: allowed values separated by '|', '<=N' / '>=N', or '' for information only.
$checks = @(
    @('SharingCapability', 'Disabled|ExistingExternalUserSharingOnly|ExternalUserSharingOnly', 'Keep Anyone links off tenant-wide; enable them per site only where needed'),
    @('DefaultSharingLinkType', 'Direct|Internal', 'Default new links to Specific people (Direct) or People in your organization (Internal)'),
    @('DefaultLinkPermission', 'View', 'Default new links to View'),
    @('RequireAnonymousLinksExpireInDays', '>=1', 'Make Anyone links expire (-1 = never); 30 days is a common choice'),
    @('FileAnonymousLinkType', 'View', 'Anyone links for files should be view-only'),
    @('FolderAnonymousLinkType', 'View', 'Anyone links for folders should be view-only'),
    @('SharingDomainRestrictionMode', '', 'AllowList with known partner domains limits guest sharing to approved organizations'),
    @('SharingAllowedDomainList', '', 'Domains allowed when the restriction mode is AllowList'),
    @('PreventExternalUsersFromResharing', 'True', 'Guests should not be able to re-share content they do not own'),
    @('RequireAcceptingAccountMatchInvitedAccount', 'True', 'Invitations must be accepted with the invited account'),
    @('ExternalUserExpirationRequired', 'True', 'Expire guest access automatically'),
    @('ExternalUserExpireInDays', '<=90', 'Guest access lifetime in days (30-90 recommended)'),
    @('NotifyOwnersWhenItemsReshared', 'True', 'Owners should be notified when their items are re-shared'),
    @('ShowEveryoneClaim', 'False', 'Hide the Everyone claim in the people picker'),
    @('ShowAllUsersClaim', 'False', 'Hide the All Users claim in the people picker'),
    @('ConditionalAccessPolicy', '', 'AllowLimitedAccess or BlockAccess for unmanaged devices, paired with a Conditional Access policy'),
    @('LegacyAuthProtocolsEnabled', 'False', 'Legacy authentication bypasses MFA and Conditional Access'),
    @('DisallowInfectedFileDownload', 'True', 'Block download of files flagged by Defender for Office 365 Safe Attachments'),
    @('MarkNewFilesSensitiveByDefault', 'BlockExternalSharing', 'Block external sharing of new files until DLP has scanned them'),
    @('EnableAIPIntegration', 'True', 'Apply sensitivity labels to Office files in SharePoint and OneDrive'),
    @('EnableRestrictedAccessControl', '', 'Restricted access control (SharePoint Advanced Management) limits site access to a group'),
    @('DisableCustomAppAuthentication', '', 'True blocks legacy ACS app-only authentication; verify integrations before enabling'),
    @('OneDriveForGuestsEnabled', 'False', 'Guests do not need their own OneDrive'),
    @('OneDriveStorageQuota', '', 'Default OneDrive quota in MB (1048576 = 1 TB)'),
    @('OrphanedPersonalSitesRetentionPeriod', '>=30', 'Days a deleted user''s OneDrive is retained (30-3650); align with offboarding'),
    @('IsUnmanagedSyncClientForTenantRestricted', '', 'True limits OneDrive sync to domain-joined devices in AllowedDomainListForSyncClient'),
    @('AllowedDomainListForSyncClient', '', 'Domain GUIDs allowed to sync when sync is restricted'),
    @('SelfServiceSiteCreationDisabled', '', 'Whether users can create sites themselves'),
    @('StorageQuota', '', 'Tenant storage quota in MB'),
    @('StorageQuotaAllocated', '', 'Tenant storage already allocated to sites in MB')
)
$assessment = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($check in $checks) {
    $value = $null
    if ($snapshot.Contains($check[0])) { $value = $snapshot[$check[0]] }
    $assessment.Add([PSCustomObject]@{
            Setting        = $check[0]
            Value          = $value
            Status         = Test-SettingValue -Value $value -Rule $check[1]
            Expected       = $check[1]
            Recommendation = $check[2]
        })
}
$assessment | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$differences = @()
if (-not [string]::IsNullOrWhiteSpace($CompareWith)) {
    try {
        $previous = Get-Content -Path $CompareWith -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        throw "Failed to read the comparison snapshot ${CompareWith}: $($_.Exception.Message)"
    }
    $previousNames = @($previous.PSObject.Properties | ForEach-Object { $_.Name })
    foreach ($name in @(@($snapshot.Keys) + $previousNames | Sort-Object -Unique)) {
        $old = ''; $new = ''
        if ($previousNames -contains $name) { $old = [string]$previous.$name }
        if ($snapshot.Contains($name)) { $new = [string]$snapshot[$name] }
        if ($old -ne $new) { $differences += [PSCustomObject]@{ Setting = $name; Previous = $old; Current = $new } }
    }
    $diffPath = ($OutputPath -replace '\.csv$', '') + '_Diff.csv'
    if ($differences.Count -gt 0) { $differences | Export-Csv -Path $diffPath -NoTypeInformation -Encoding UTF8 }
}

Write-Host ''
Write-Host 'SharePoint tenant settings summary' -ForegroundColor Cyan
Write-Host ('  Tenant properties exported : {0} -> {1}' -f $snapshot.Count, $JsonPath)
$statusColours = @{ Compliant = 'Green'; Review = 'Yellow'; Info = 'Gray'; NotAvailable = 'Gray' }
foreach ($group in ($assessment | Group-Object -Property Status | Sort-Object -Property Name)) {
    Write-Host ('  {0,-27}: {1}' -f $group.Name, $group.Count) -ForegroundColor $statusColours[$group.Name]
}
foreach ($item in ($assessment | Where-Object { $_.Status -eq 'Review' })) { Write-Host ('    {0,-45} = {1}' -f $item.Setting, $item.Value) -ForegroundColor Yellow }
if (-not [string]::IsNullOrWhiteSpace($CompareWith)) {
    Write-Host ('  Changed since snapshot     : {0}' -f $differences.Count) -ForegroundColor Yellow
    foreach ($difference in $differences) { Write-Host ('    {0}: {1} -> {2}' -f $difference.Setting, $difference.Previous, $difference.Current) }
}
Write-Host ('  Assessment exported        : {0} -> {1}' -f $assessment.Count, $OutputPath)

if ($PassThru) { $assessment }
#endregion Main
