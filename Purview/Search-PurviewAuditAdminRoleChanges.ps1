<#
.SYNOPSIS
    Reports Entra ID directory role membership changes (and optionally group membership changes) from the unified audit log.
.DESCRIPTION
    Searches RecordType AzureActiveDirectory for the add/remove (eligible) member to role operations one day at a time with
    Search-UnifiedAuditLog (ReturnLargeSet paging), parses AuditData and resolves the actor, the target UPN (Target type 5)
    and the role or group name and template ID from ModifiedProperties. Rows are flagged for privileged roles, changes made
    outside PIM and changes outside business hours. Exports a CSV and prints counts by role and actor.
.PARAMETER DaysBack
    Number of days to search back from now (default 7, maximum 180). Ignored when -StartDate is used.
.PARAMETER StartDate
    Start of the search window (UTC). Use with -EndDate instead of -DaysBack.
.PARAMETER EndDate
    End of the search window (UTC). Defaults to now.
.PARAMETER UserIds
    One or more actor user principal names to filter on (the admin who made the change).
.PARAMETER IncludeGroupChanges
    Also include 'Add member to group.' and 'Remove member from group.' (role-assignable and regular groups).
.PARAMETER BusinessHoursStart
    First hour (0-23, UTC) of the business day used for the out-of-hours flag. Default 8.
.PARAMETER BusinessHoursEnd
    Hour (1-24, UTC) at which the business day ends for the out-of-hours flag. Default 18. Weekends are always out of hours.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\PurviewAuditAdminRoleChanges_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emit the flattened records to the pipeline.
.EXAMPLE
    PS> .\Search-PurviewAuditAdminRoleChanges.ps1
    Exports the role membership changes of the last 7 days and prints who changed which roles.
.EXAMPLE
    PS> .\Search-PurviewAuditAdminRoleChanges.ps1 -DaysBack 90 -IncludeGroupChanges -BusinessHoursStart 7 -BusinessHoursEnd 19 -PassThru | Where-Object { $_.IsPrivilegedRole -and -not $_.ViaPim }
    Finds direct (non-PIM) changes to Global, Privileged Role or Security Administrator over the last quarter.
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
                  into one-day searches because a ReturnLargeSet session returns at most 50,000 records. Times are UTC, so set the
                  business hours in UTC. PIM activations are logged with actor MS-PIM. Beyond 90 days a warning is shown.
.LINK
    https://learn.microsoft.com/powershell/module/exchange/search-unifiedauditlog
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
    [switch]$IncludeGroupChanges,

    [Parameter()]
    [ValidateRange(0, 23)]
    [int]$BusinessHoursStart = 8,

    [Parameter()]
    [ValidateRange(1, 24)]
    [int]$BusinessHoursEnd = 18,

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
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('PurviewAuditAdminRoleChanges_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
try { Connect-ExchangeIfNeeded } catch { throw "Unable to connect to Exchange Online: $($_.Exception.Message)" }
$operations = @('Add member to role.', 'Remove member from role.', 'Add eligible member to role.', 'Remove eligible member from role.')
if ($IncludeGroupChanges) { $operations += 'Add member to group.', 'Remove member from group.' }
# One search session per day keeps every slice under the 50,000-record ReturnLargeSet ceiling.
$records = New-Object -TypeName System.Collections.Generic.List[object]
$totalDays = [int][math]::Ceiling(($EndDate - $StartDate).TotalDays)
for ($day = 0; $day -lt $totalDays; $day++) {
    $sliceStart = $StartDate.AddDays($day)
    $sliceEnd = $StartDate.AddDays($day + 1)
    if ($sliceEnd -gt $EndDate) { $sliceEnd = $EndDate }
    Write-Progress -Activity 'Audit log search' -Status ('Day {0}/{1} ({2:yyyy-MM-dd}): {3} records' -f ($day + 1), $totalDays, $sliceStart, $records.Count) -PercentComplete (100 * $day / $totalDays)
    try { $records.AddRange(@(Search-AuditRecords -StartDate $sliceStart -EndDate $sliceEnd -RecordType 'AzureActiveDirectory' -Operations $operations -UserIds $UserIds)) }
    catch { Write-Warning ('Search for {0:yyyy-MM-dd} failed: {1}' -f $sliceStart, $_.Exception.Message) }
}
Write-Progress -Activity 'Audit log search' -Completed
$privilegedRoles = @('Global Administrator', 'Company Administrator', 'Privileged Role Administrator', 'Security Administrator')  # Company Administrator = legacy name of Global Administrator
$results = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($record in $records) {
    try { $audit = [string]$record.AuditData | ConvertFrom-Json -ErrorAction Stop }
    catch { Write-Warning "Could not parse AuditData for record $($record.Identity); skipped."; continue }
    $targetUpn = [string](@($audit.Target | Where-Object { $_.Type -eq 5 } | Select-Object -First 1).ID)
    if (-not $targetUpn) { $targetUpn = @($audit.Target | ForEach-Object { $_.ID }) -join '; ' }
    $modified = @($audit.ModifiedProperties)
    $roleProperty = @($modified | Where-Object { 'Role.DisplayName', 'Group.DisplayName' -contains $_.Name } | Select-Object -First 1)
    $roleName = ([string]$(if ($roleProperty.NewValue) { $roleProperty.NewValue } else { $roleProperty.OldValue })).Trim('"')
    $when = [datetime]$record.CreationDate
    $results.Add([PSCustomObject]@{
            CreationTime     = $when
            Operation        = [string]$audit.Operation
            Actor            = [string]$audit.UserId
            Target           = $targetUpn
            RoleOrGroup      = $roleName
            TemplateId       = ([string](@($modified | Where-Object { $_.Name -eq 'Role.TemplateId' } | Select-Object -First 1).NewValue)).Trim('"')
            ResultStatus     = [string]$audit.ResultStatus
            ClientIP         = [string]$audit.ActorIpAddress
            IsPrivilegedRole = ($privilegedRoles -contains $roleName)
            ViaPim           = ([string]$audit.UserId -eq 'MS-PIM')
            IsOutOfHours     = ($when.Hour -lt $BusinessHoursStart -or $when.Hour -ge $BusinessHoursEnd -or $when.DayOfWeek -eq 'Saturday' -or $when.DayOfWeek -eq 'Sunday')
        })
}
$results = @($results | Sort-Object -Property CreationTime)
if ($results.Count -gt 0) { $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
Write-Host 'Admin role change summary' -ForegroundColor Cyan
Write-Host ('  Window              : {0:yyyy-MM-dd HH:mm} to {1:yyyy-MM-dd HH:mm} UTC, {2} change(s) in {3} day slice(s)' -f $StartDate, $EndDate, $results.Count, $totalDays)
Write-Host ('  Privileged roles    : {0}' -f @($results | Where-Object { $_.IsPrivilegedRole }).Count) -ForegroundColor Yellow
Write-Host ('  Outside PIM         : {0}  (actor is not MS-PIM)' -f @($results | Where-Object { -not $_.ViaPim }).Count)
Write-Host ('  Out of hours        : {0}  (outside {1:00}:00-{2:00}:00 UTC or weekend)' -f @($results | Where-Object { $_.IsOutOfHours }).Count, $BusinessHoursStart, $BusinessHoursEnd)
Write-Host '  By role or group:'
foreach ($group in ($results | Group-Object -Property RoleOrGroup | Sort-Object -Property Count -Descending | Select-Object -First 10)) { Write-Host ('    {0,7}  {1}' -f $group.Count, $group.Name) }
Write-Host '  By actor:'
foreach ($group in ($results | Group-Object -Property Actor | Sort-Object -Property Count -Descending | Select-Object -First 10)) { Write-Host ('    {0,7}  {1}' -f $group.Count, $group.Name) }
Write-Host ('  Report              : {0}' -f $OutputPath)
if ($PassThru) { $results }
#endregion Main
