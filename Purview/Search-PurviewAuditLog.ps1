<#
.SYNOPSIS
    Exports unified audit log records reliably, beyond the 5,000-row limit of a single Search-UnifiedAuditLog call.
.DESCRIPTION
    Slices the requested window into -IntervalHours blocks and, for each block, pages through
    Search-UnifiedAuditLog with -SessionCommand ReturnLargeSet until the service reports that every record has
    been returned. Records are de-duplicated by Identity, the AuditData JSON is parsed, and common fields
    (Workload, ClientIP, ObjectId, ResultStatus, UserAgent, UserType) are flattened into columns while the raw
    AuditData JSON is kept for deeper analysis. Optional filters cover users, operations, record type, free text
    and IP addresses. Writes a CSV and prints a summary by operation and workload. The script is read-only.
.PARAMETER StartDate
    Start of the search window. Defaults to 7 days ago. Must be within the audit retention period (180 days by default).
.PARAMETER EndDate
    End of the search window. Defaults to now and must be later than StartDate.
.PARAMETER UserIds
    One or more user principal names to filter on.
.PARAMETER Operations
    One or more operations, for example FileDownloaded, UserLoggedIn, 'Add member to role.'.
.PARAMETER RecordType
    A single audit record type, for example ExchangeItem, SharePointFileOperation or AzureActiveDirectoryStsLogon.
.PARAMETER FreeText
    Free-text filter applied by the service to the audit record.
.PARAMETER IPAddresses
    One or more client IP addresses to filter on.
.PARAMETER IntervalHours
    Size of each time slice in hours (default 24). Use smaller slices for busy tenants so that no slice exceeds
    the 50,000 records that a ReturnLargeSet session can page through.
.PARAMETER ResultSize
    Page size per Search-UnifiedAuditLog call, 1-5000 (default 5000).
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\PurviewAuditLog_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the flattened records to the pipeline.
.EXAMPLE
    PS> .\Search-PurviewAuditLog.ps1
    Exports the last 7 days of audit records for the whole tenant to .\Reports\PurviewAuditLog_<timestamp>.csv.
.EXAMPLE
    PS> .\Search-PurviewAuditLog.ps1 -StartDate (Get-Date).AddDays(-30) -UserIds alex@contoso.com -Operations UserLoggedIn, FileDownloaded -IntervalHours 12 -Verbose
    Exports 30 days of sign-in and download events for one user in 12-hour slices.
.EXAMPLE
    PS> .\Search-PurviewAuditLog.ps1 -RecordType AzureActiveDirectoryStsLogon -IPAddresses 203.0.113.10 -PassThru | Group-Object UserIds | Sort-Object Count -Descending
    Shows who signed in from a specific IP address during the last 7 days.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-03
    Requires    : PowerShell 5.1 or 7.x, ExchangeOnlineManagement 3.x
    Permissions : Audit Logs or View-Only Audit Logs role (Exchange Online / Purview); auditing must be enabled
                  (Get-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled)
    Category    : Audit log scenarios
    Changes     : No
    Notes       : Search-UnifiedAuditLog is an Exchange Online cmdlet, so the script opens an Exchange Online session,
                  not a Security & Compliance one. Audit (Standard) retains 180 days; Audit (Premium) retention policies
                  can keep selected records for up to 10 years. Dates are interpreted by the service as UTC and
                  CreationDate is returned in UTC. Searches are throttled per tenant - avoid running several exports
                  at the same time, and prefer smaller -IntervalHours over huge single sessions.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/search-unifiedauditlog
.LINK
    https://learn.microsoft.com/purview/audit-log-search-script
#>
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

[CmdletBinding()]
param(
    [Parameter()]
    [datetime]$StartDate = (Get-Date).AddDays(-7),

    [Parameter()]
    [datetime]$EndDate = (Get-Date),

    [Parameter()]
    [string[]]$UserIds,

    [Parameter()]
    [string[]]$Operations,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$RecordType,

    [Parameter()]
    [string]$FreeText,

    [Parameter()]
    [string[]]$IPAddresses,

    [Parameter()]
    [ValidateRange(1, 720)]
    [int]$IntervalHours = 24,

    [Parameter()]
    [ValidateRange(1, 5000)]
    [int]$ResultSize = 5000,

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

function Get-AuditField {
    <# Returns the first non-empty value among the given property names of a parsed AuditData object; workloads name the same field differently. #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowNull()]
        $AuditData,

        [Parameter(Mandatory = $true)]
        [string[]]$Names
    )
    if ($null -eq $AuditData) { return $null }
    foreach ($name in $Names) {
        $property = $AuditData.PSObject.Properties[$name]
        if ($null -ne $property -and -not [string]::IsNullOrEmpty([string]$property.Value)) { return $property.Value }
    }
    return $null
}
#endregion Helpers

#region Main
if ($EndDate -le $StartDate) { throw 'EndDate must be later than StartDate.' }
if ($StartDate -lt (Get-Date).AddDays(-180)) {
    Write-Warning 'StartDate is more than 180 days ago. Audit (Standard) keeps records for 180 days; older events are only returned when Audit (Premium) retention policies apply.'
}

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('PurviewAuditLog_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try {
    Connect-ExchangeIfNeeded
}
catch {
    throw "Unable to connect to Exchange Online: $($_.Exception.Message)"
}

try {
    $auditConfig = Get-AdminAuditLogConfig -ErrorAction Stop
    if ($auditConfig.UnifiedAuditLogIngestionEnabled -ne $true) {
        Write-Warning 'Unified audit log ingestion is disabled for this tenant. Enable it with Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true; searches return nothing until then.'
    }
}
catch {
    Write-Verbose "Could not read the audit configuration (requires the Organization Configuration role): $($_.Exception.Message)"
}

$filterParams = @{}
if ($PSBoundParameters.ContainsKey('UserIds')) { $filterParams['UserIds'] = $UserIds }
if ($PSBoundParameters.ContainsKey('Operations')) { $filterParams['Operations'] = $Operations }
if ($PSBoundParameters.ContainsKey('RecordType')) { $filterParams['RecordType'] = $RecordType }
if ($PSBoundParameters.ContainsKey('FreeText')) { $filterParams['FreeText'] = $FreeText }
if ($PSBoundParameters.ContainsKey('IPAddresses')) { $filterParams['IPAddresses'] = $IPAddresses }

# A ReturnLargeSet session can page through at most 50,000 records; this caps the paging loop per slice.
$maxPages = [int][math]::Ceiling(50000 / $ResultSize)
$totalSlices = [int][math]::Ceiling(($EndDate - $StartDate).TotalHours / $IntervalHours)
$records = New-Object -TypeName System.Collections.Generic.List[object]
$seen = New-Object -TypeName 'System.Collections.Generic.HashSet[string]'
$sliceIndex = 0
$sliceStart = $StartDate
while ($sliceStart -lt $EndDate) {
    $sliceIndex++
    $sliceEnd = $sliceStart.AddHours($IntervalHours)
    if ($sliceEnd -gt $EndDate) { $sliceEnd = $EndDate }
    $status = 'Slice {0} of {1}: {2:yyyy-MM-dd HH:mm} to {3:yyyy-MM-dd HH:mm} ({4} records so far)' -f $sliceIndex, $totalSlices, $sliceStart, $sliceEnd, $records.Count
    Write-Progress -Activity 'Searching the unified audit log' -Status $status -PercentComplete ((($sliceIndex - 1) / $totalSlices) * 100)

    # A new SessionId per slice starts a fresh paged result set on the service side.
    $searchParams = @{
        StartDate      = $sliceStart
        EndDate        = $sliceEnd
        SessionId      = [guid]::NewGuid().ToString()
        SessionCommand = 'ReturnLargeSet'
        ResultSize     = $ResultSize
        ErrorAction    = 'Stop'
    } + $filterParams
    $expectedCount = 0
    $sliceRecords = 0
    $page = 1
    do {
        try {
            $batch = @(Search-UnifiedAuditLog @searchParams)
        }
        catch {
            Write-Warning ('Slice {0} ({1:yyyy-MM-dd HH:mm} to {2:yyyy-MM-dd HH:mm}), page {3} failed: {4}' -f $sliceIndex, $sliceStart, $sliceEnd, $page, $_.Exception.Message)
            break
        }
        if ($batch.Count -eq 0) { break }
        if ($page -eq 1) {
            $expectedCount = [int]$batch[0].ResultCount
            if ($expectedCount -ge 50000) {
                Write-Warning ('Slice {0} holds {1} records but ReturnLargeSet pages through at most 50,000. Re-run with a smaller -IntervalHours to capture everything.' -f $sliceIndex, $expectedCount)
            }
        }
        foreach ($entry in $batch) {
            if ($seen.Add([string]$entry.Identity)) { $records.Add($entry) }
        }
        $sliceRecords += $batch.Count
        Write-Verbose ('Slice {0}, page {1}: {2} records ({3} of {4}).' -f $sliceIndex, $page, $batch.Count, $sliceRecords, $expectedCount)
        $page++
    } while ($sliceRecords -lt $expectedCount -and $page -le $maxPages)
    $sliceStart = $sliceEnd
}
Write-Progress -Activity 'Searching the unified audit log' -Completed

# UserType in AuditData is numeric; these are the documented values.
$userTypeNames = @{ '0' = 'Regular'; '1' = 'Reserved'; '2' = 'Admin'; '3' = 'DcAdmin'; '4' = 'System'; '5' = 'Application'; '6' = 'ServicePrincipal'; '7' = 'CustomPolicy'; '8' = 'SystemPolicy' }
$results = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($record in $records) {
    $audit = $null
    try {
        $audit = [string]$record.AuditData | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Write-Verbose "Could not parse AuditData for record $($record.Identity): $($_.Exception.Message)"
    }

    $userAgent = Get-AuditField -AuditData $audit -Names 'UserAgent', 'ClientInfoString'
    if ($null -eq $userAgent -and $null -ne $audit -and $null -ne $audit.PSObject.Properties['ExtendedProperties']) {
        # Entra ID sign-in events carry the user agent inside ExtendedProperties.
        $extended = @($audit.ExtendedProperties | Where-Object { $_.Name -eq 'UserAgent' }) | Select-Object -First 1
        if ($null -ne $extended) { $userAgent = $extended.Value }
    }
    $userType = [string](Get-AuditField -AuditData $audit -Names 'UserType')
    if ($userTypeNames.ContainsKey($userType)) { $userType = $userTypeNames[$userType] }

    $results.Add([PSCustomObject]@{
            CreationDate = [datetime]$record.CreationDate
            UserIds      = [string]$record.UserIds
            Operations   = [string]$record.Operations
            RecordType   = [string]$record.RecordType
            Workload     = [string](Get-AuditField -AuditData $audit -Names 'Workload')
            ClientIP     = [string](Get-AuditField -AuditData $audit -Names 'ClientIP', 'ClientIPAddress', 'ActorIpAddress')
            ObjectId     = [string](Get-AuditField -AuditData $audit -Names 'ObjectId')
            ResultStatus = [string](Get-AuditField -AuditData $audit -Names 'ResultStatus')
            UserAgent    = [string]$userAgent
            UserType     = $userType
            Id           = [string](Get-AuditField -AuditData $audit -Names 'Id')
            AuditData    = [string]$record.AuditData
        })
}
$results = @($results | Sort-Object -Property CreationDate)

if ($results.Count -gt 0) {
    $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
}
else {
    Write-Warning 'The search returned no audit records for the given window and filters.'
}

Write-Host ''
Write-Host 'Unified audit log search summary' -ForegroundColor Cyan
Write-Host ('  Window         : {0:yyyy-MM-dd HH:mm} to {1:yyyy-MM-dd HH:mm} in {2} slice(s) of {3} h' -f $StartDate, $EndDate, $totalSlices, $IntervalHours)
Write-Host ('  Records        : {0}' -f $results.Count)
if ($results.Count -gt 0) {
    Write-Host '  Top operations :'
    foreach ($group in ($results | Group-Object -Property Operations | Sort-Object -Property Count -Descending | Select-Object -First 10)) {
        Write-Host ('    {0,7}  {1}' -f $group.Count, $group.Name)
    }
    Write-Host '  By workload    :'
    foreach ($group in ($results | Group-Object -Property Workload | Sort-Object -Property Count -Descending)) {
        Write-Host ('    {0,7}  {1}' -f $group.Count, $(if ([string]::IsNullOrWhiteSpace($group.Name)) { '(not in AuditData)' } else { $group.Name }))
    }
    Write-Host ('  Report         : {0}' -f $OutputPath)
}

if ($PassThru) {
    $results
}
#endregion Main
