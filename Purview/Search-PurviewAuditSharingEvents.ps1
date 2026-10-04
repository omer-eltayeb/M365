<#
.SYNOPSIS
    Reports SharePoint and OneDrive sharing events (invitations, links, permission grants) from the unified audit log.
.DESCRIPTION
    Searches RecordType SharePointSharingOperation with Search-UnifiedAuditLog one day at a time (ReturnLargeSet paging),
    parses AuditData and flattens who shared what with whom, including the link type or permission in EventData. Rows are
    flagged when the target is external (guest or a domain outside -InternalDomains) or an anonymous link was involved.
    Exports a CSV and prints counts by user, site and external target plus the external and anonymous-link totals.
.PARAMETER DaysBack
    Number of days to search back from now (default 7, maximum 180). Ignored when -StartDate is used.
.PARAMETER StartDate
    Start of the search window (UTC). Use with -EndDate instead of -DaysBack.
.PARAMETER EndDate
    End of the search window (UTC). Defaults to now.
.PARAMETER UserIds
    One or more user principal names (the sharing users) to filter on.
.PARAMETER Operations
    Sharing operations to include. Defaults to sharing set/revoked, invitations, anonymous, secure and company links.
.PARAMETER InternalDomains
    Your accepted domains, for example contoso.com, contoso.onmicrosoft.com. Targets in other domains are flagged as external.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\PurviewAuditSharingEvents_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the flattened records to the pipeline.
.EXAMPLE
    PS> .\Search-PurviewAuditSharingEvents.ps1 -InternalDomains contoso.com, contoso.onmicrosoft.com
    Exports the last 7 days of sharing events and flags every share to a guest or to an address outside the two domains.
.EXAMPLE
    PS> .\Search-PurviewAuditSharingEvents.ps1 -DaysBack 30 -Operations AnonymousLinkCreated, AnonymousLinkUsed -PassThru | Group-Object SiteUrl
    Shows which sites had anonymous links created or used in the last 30 days.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Audit Logs or View-Only Audit Logs role (Exchange Online / Purview); unified audit log ingestion must be enabled
    Category    : Audit log scenarios
    Changes     : No
    Notes       : Uses an Exchange Online session because Search-UnifiedAuditLog is an Exchange Online cmdlet. The window is sliced
                  into one-day searches because a ReturnLargeSet session returns at most 50,000 records. Dates are UTC. Without
                  -InternalDomains only guest accounts and #EXT# names are flagged as external. Audit (Standard) keeps 180 days;
                  beyond 90 days a warning is shown because older records may need Audit (Premium) retention policies.
.LINK
    https://learn.microsoft.com/purview/audit-log-sharing
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding(DefaultParameterSetName = 'DaysBack')]
param(
    [Parameter(ParameterSetName = 'DaysBack')]
    [ValidateRange(1, 180)]
    [int]$DaysBack = 7,

    [Parameter(Mandatory = $true, ParameterSetName = 'Dates')]
    [datetime]$StartDate,

    [Parameter(ParameterSetName = 'Dates')]
    [datetime]$EndDate = (Get-Date),

    [Parameter()]
    [string[]]$UserIds,

    [Parameter()]
    [string[]]$Operations = @('SharingSet', 'SharingInvitationCreated', 'SharingInvitationAccepted', 'SharingRevoked', 'AnonymousLinkCreated',
        'AnonymousLinkUsed', 'AnonymousLinkUpdated', 'AnonymousLinkRemoved', 'SecureLinkCreated', 'SecureLinkUsed', 'SecureLinkUpdated',
        'AddedToSecureLink', 'RemovedFromSecureLink', 'CompanyLinkCreated', 'CompanyLinkUsed'),

    [Parameter()]
    [string[]]$InternalDomains,

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'

#region Helpers
function Connect-ExchangeIfNeeded {
    <# Connects to Exchange Online (or Security & Compliance PowerShell) only when no live session exists. #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [switch]$Compliance
    )
    $connections = @(Get-ConnectionInformation -ErrorAction SilentlyContinue)
    if ($Compliance) {
        $active = @($connections | Where-Object { $_.ConnectionUri -like '*compliance*' -and $_.State -eq 'Connected' })
        if ($active.Count -eq 0) {
            Write-Verbose 'Connecting to Security & Compliance PowerShell.'
            Connect-IPPSSession -ErrorAction Stop
        }
    }
    else {
        $active = @($connections | Where-Object { $_.ConnectionUri -notlike '*compliance*' -and $_.State -eq 'Connected' })
        if ($active.Count -eq 0) {
            Write-Verbose 'Connecting to Exchange Online.'
            Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        }
    }
}

function Search-AuditRecords {
    <# Pages through Search-UnifiedAuditLog with ReturnLargeSet and returns de-duplicated records. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [datetime]$StartDate,

        [Parameter(Mandatory = $true)]
        [datetime]$EndDate,

        [Parameter()]
        [string[]]$RecordType,

        [Parameter()]
        [string[]]$Operations,

        [Parameter()]
        [string[]]$UserIds,

        [Parameter()]
        [string]$FreeText
    )
    $sessionId = [guid]::NewGuid().ToString()
    $records = New-Object -TypeName System.Collections.Generic.List[object]
    $seen = @{}
    do {
        $searchParams = @{ StartDate = $StartDate; EndDate = $EndDate; SessionId = $sessionId; SessionCommand = 'ReturnLargeSet'; ResultSize = 5000; ErrorAction = 'Stop' }
        if ($RecordType) { $searchParams['RecordType'] = $RecordType }
        if ($Operations) { $searchParams['Operations'] = $Operations }
        if ($UserIds) { $searchParams['UserIds'] = $UserIds }
        if ($FreeText) { $searchParams['FreeText'] = $FreeText }
        $page = @(Search-UnifiedAuditLog @searchParams)
        foreach ($record in $page) {
            if (-not $seen.ContainsKey($record.Identity)) {
                $seen[$record.Identity] = $true
                $records.Add($record)
            }
        }
    } while ($page.Count -gt 0)
    return $records
}
#endregion Helpers

#region Main
if ($PSCmdlet.ParameterSetName -eq 'DaysBack') { $StartDate = (Get-Date).AddDays(-$DaysBack) }
if ($EndDate -le $StartDate) { throw 'EndDate must be later than StartDate.' }
if (($EndDate - $StartDate).TotalDays -gt 90) { Write-Warning 'Window longer than 90 days: records beyond Audit (Standard) retention need Audit (Premium) retention policies.' }
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('PurviewAuditSharingEvents_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
try { Connect-ExchangeIfNeeded } catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }

# One search session per day keeps every slice under the 50,000-record ReturnLargeSet ceiling.
$records = New-Object -TypeName System.Collections.Generic.List[object]
$totalDays = [int][math]::Ceiling(($EndDate - $StartDate).TotalDays)
for ($day = 0; $day -lt $totalDays; $day++) {
    $sliceStart = $StartDate.AddDays($day)
    $sliceEnd = $StartDate.AddDays($day + 1)
    if ($sliceEnd -gt $EndDate) { $sliceEnd = $EndDate }
    Write-Progress -Activity 'Audit log search' -Status ('Day {0}/{1} ({2:yyyy-MM-dd}): {3} records' -f ($day + 1), $totalDays, $sliceStart, $records.Count) -PercentComplete (100 * $day / $totalDays)
    try { $records.AddRange(@(Search-AuditRecords -StartDate $sliceStart -EndDate $sliceEnd -RecordType 'SharePointSharingOperation' -Operations $Operations -UserIds $UserIds)) }
    catch { Write-Warning ('Search for {0:yyyy-MM-dd} failed: {1}' -f $sliceStart, $_.Exception.Message) }
}
Write-Progress -Activity 'Audit log search' -Completed
$results = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($record in $records) {
    try { $audit = [string]$record.AuditData | ConvertFrom-Json -ErrorAction Stop }
    catch { Write-Warning "Could not parse AuditData for record $($record.Identity); skipped."; continue }
    $target = [string]$audit.TargetUserOrGroupName
    $targetType = [string]$audit.TargetUserOrGroupType
    $targetDomain = $(if ($target -like '*@*') { $target.Split('@')[-1] } else { '' })
    $isExternal = ($targetType -eq 'Guest') -or ($target -like '*#EXT#*') -or ($InternalDomains -and $targetDomain -and ($InternalDomains -notcontains $targetDomain))
    $results.Add([PSCustomObject]@{
            CreationTime          = [datetime]$record.CreationDate
            Operation             = [string]$audit.Operation
            UserId                = [string]$audit.UserId
            SiteUrl               = [string]$audit.SiteUrl
            ObjectId              = [string]$audit.ObjectId
            SourceFileName        = [string]$audit.SourceFileName
            TargetUserOrGroupName = $target
            TargetUserOrGroupType = $targetType
            IsExternalTarget      = [bool]$isExternal
            IsAnonymousLink       = ([string]$audit.Operation -like 'AnonymousLink*')
            EventData             = ([regex]::Replace([string]$audit.EventData, '<(\w+)>([^<]*)</\1>', '$1=$2 ')).Trim()  # <Name>Value</Name> becomes Name=Value
            ClientIP              = [string]$audit.ClientIP
            UniqueSharingId       = [string]$audit.UniqueSharingId
        })
}
$results = @($results | Sort-Object -Property CreationTime)
if ($results.Count -gt 0) { $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'The search returned no sharing events for the given window and filters.' }
$external = @($results | Where-Object { $_.IsExternalTarget })
$anonymous = @($results | Where-Object { $_.IsAnonymousLink })
Write-Host 'Sharing events summary' -ForegroundColor Cyan
Write-Host ('  Window           : {0:yyyy-MM-dd HH:mm} to {1:yyyy-MM-dd HH:mm} UTC, {2} record(s) in {3} day slice(s)' -f $StartDate, $EndDate, $results.Count, $totalDays)
Write-Host ('  External targets : {0}  (guest, #EXT# or outside -InternalDomains)' -f $external.Count) -ForegroundColor $(if ($external.Count -gt 0) { 'Yellow' } else { 'Green' })
Write-Host ('  Anonymous links  : {0}' -f $anonymous.Count) -ForegroundColor $(if ($anonymous.Count -gt 0) { 'Yellow' } else { 'Green' })
Write-Host '  Top sharing users:'
foreach ($group in ($results | Group-Object -Property UserId | Sort-Object -Property Count -Descending | Select-Object -First 10)) { Write-Host ('    {0,7}  {1}' -f $group.Count, $group.Name) }
Write-Host '  Top sites:'
foreach ($group in ($results | Group-Object -Property SiteUrl | Sort-Object -Property Count -Descending | Select-Object -First 10)) { Write-Host ('    {0,7}  {1}' -f $group.Count, $group.Name) }
Write-Host '  Top external targets:'
foreach ($group in ($external | Group-Object -Property TargetUserOrGroupName | Sort-Object -Property Count -Descending | Select-Object -First 10)) {
    Write-Host ('    {0,7}  {1}' -f $group.Count, $group.Name)
}
Write-Host ('  Report           : {0}' -f $OutputPath)
if ($PassThru) { $results }
#endregion Main
