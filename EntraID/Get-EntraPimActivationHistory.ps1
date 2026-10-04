<#
.SYNOPSIS
    Reports Privileged Identity Management (PIM) activation and assignment requests for Microsoft Entra directory roles.
.DESCRIPTION
    Reads the PIM request history (GET /roleManagement/directory/roleAssignmentScheduleRequests filtered on createdDateTime,
    expanded with principal and roleDefinition) for the last N days: one row per request with action (selfActivate, adminAssign,
    adminRemove, ...), status, role, principal, justification, ticket, schedule, duration and creator. Requests created outside
    business hours or on a weekend are flagged. Exports to CSV with per-action, per-role and per-principal counts.
.PARAMETER DaysBack
    How many days of request history to read. Default 30.
.PARAMETER RoleName
    Only requests for roles whose display name matches this wildcard pattern, for example 'Global*'.
.PARAMETER UserPrincipalName
    Only requests whose principal UPN (or group mail / app id) matches this wildcard pattern, for example 'adm-*'.
.PARAMETER ActionFilter
    Only requests with one of these actions, for example selfActivate or adminAssign.
.PARAMETER BusinessHoursStart
    Hour (0-23) at which business hours start, in the local time zone of the machine running the script. Default 8.
.PARAMETER BusinessHoursEnd
    Hour (1-24, exclusive) at which business hours end, in the local time zone of the machine. Default 18.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EntraPimActivationHistory_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-EntraPimActivationHistory.ps1
    Exports every PIM request from the last 30 days and prints the counts per action, role and principal.
.EXAMPLE
    PS> .\Get-EntraPimActivationHistory.ps1 -DaysBack 7 -ActionFilter selfActivate -RoleName 'Global Administrator' -PassThru
    Lists last week's Global Administrator self-activations in the console.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : RoleAssignmentSchedule.Read.Directory, RoleManagement.Read.Directory, Directory.Read.All (delegated).
    Category    : Roles, governance & tenant policy
    Changes     : No
    Notes       : Requires Microsoft Entra ID P2 or Entra ID Governance. Graph keeps completed request objects for a limited
                  period only (use the audit log for older history). OutsideBusinessHours uses the local clock of the machine.
.LINK
    https://learn.microsoft.com/graph/api/rbacapplication-list-roleassignmentschedulerequests
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$DaysBack = 30,

    [Parameter()]
    [string]$RoleName,

    [Parameter()]
    [string]$UserPrincipalName,

    [Parameter()]
    [ValidateSet('selfActivate', 'selfDeactivate', 'selfExtend', 'selfRenew', 'adminAssign', 'adminRemove', 'adminUpdate', 'adminExtend', 'adminRenew')]
    [string[]]$ActionFilter,

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
function Connect-GraphIfNeeded {
    <# Connects to Microsoft Graph only when there is no usable session for the required scopes. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Scopes
    )
    $context = Get-MgContext
    $missingScopes = @()
    if ($null -ne $context) {
        $missingScopes = @($Scopes | Where-Object { $context.Scopes -notcontains $_ })
    }
    if ($null -eq $context -or $missingScopes.Count -gt 0) {
        Write-Verbose "Connecting to Microsoft Graph with scopes: $($Scopes -join ', ')"
        Connect-MgGraph -Scopes $Scopes -NoWelcome -ErrorAction Stop | Out-Null
    }
    else {
        Write-Verbose "Reusing existing Microsoft Graph session for $($context.Account)."
    }
}

function Invoke-GraphPaged {
    <# GET helper that follows @odata.nextLink and returns every item in 'value'. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter()]
        [hashtable]$Headers
    )
    $results = New-Object -TypeName System.Collections.Generic.List[object]
    $nextLink = $Uri
    while (-not [string]::IsNullOrEmpty($nextLink)) {
        $requestParams = @{ Method = 'GET'; Uri = $nextLink; OutputType = 'PSObject'; ErrorAction = 'Stop' }
        if ($null -ne $Headers) { $requestParams['Headers'] = $Headers }
        $response = Invoke-MgGraphRequest @requestParams
        if ($null -ne $response.PSObject.Properties['value']) {
            foreach ($item in $response.value) { $results.Add($item) }
        }
        elseif ($null -ne $response) {
            $results.Add($response)
        }
        $nextLink = $response.'@odata.nextLink'
    }
    return $results
}

function ConvertTo-UtcDateTime {
    <# Normalises a Graph date value (ISO 8601 string or [datetime]) to a UTC [datetime]; returns $null when empty. #>
    param([object]$Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    return ([datetime]$Value).ToUniversalTime()
}
#endregion Helpers

#region Main
if ($BusinessHoursEnd -le $BusinessHoursStart) { throw 'BusinessHoursEnd must be later than BusinessHoursStart.' }
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EntraPimActivationHistory_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-GraphIfNeeded -Scopes @('RoleAssignmentSchedule.Read.Directory', 'RoleManagement.Read.Directory', 'Directory.Read.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

$since = [datetime]::UtcNow.AddDays(-$DaysBack).ToString('yyyy-MM-ddTHH:mm:ssZ')
$uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleRequests?`$filter=createdDateTime ge $since&`$expand=principal,roleDefinition"
try { $requests = Invoke-GraphPaged -Uri $uri }
catch { throw "Failed to read PIM requests (requires Microsoft Entra ID P2 and the listed scopes): $($_.Exception.Message)" }
Write-Verbose "Loaded $($requests.Count) PIM requests created since $since."

$rows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($request in $requests) {
    $principal = $request.principal
    $roleDisplayName = $request.roleDefinition.displayName
    if ([string]::IsNullOrEmpty($roleDisplayName)) { $roleDisplayName = [string]$request.roleDefinitionId }
    # Users carry a UPN, groups a mail address and service principals an app id; take whichever exists.
    $principalUpn = @($principal.userPrincipalName, $principal.mail, $principal.appId) | Where-Object { -not [string]::IsNullOrEmpty($_) } | Select-Object -First 1
    if ($PSBoundParameters.ContainsKey('ActionFilter') -and $ActionFilter -notcontains $request.action) { continue }
    if (-not [string]::IsNullOrWhiteSpace($RoleName) -and $roleDisplayName -notlike $RoleName) { continue }
    if (-not [string]::IsNullOrWhiteSpace($UserPrincipalName) -and ([string]$principalUpn) -notlike $UserPrincipalName) { continue }
    $created = ConvertTo-UtcDateTime -Value $request.createdDateTime
    $createdLocal = $outsideHours = $null
    if ($null -ne $created) {
        $createdLocal = $created.ToLocalTime()
        $outsideHours = $createdLocal.Hour -lt $BusinessHoursStart -or $createdLocal.Hour -ge $BusinessHoursEnd -or $createdLocal.DayOfWeek -in 'Saturday', 'Sunday'
    }
    # The requested duration is ISO 8601 (for example PT8H or P1D); XmlConvert turns it into a TimeSpan.
    $expiration = $request.scheduleInfo.expiration
    $durationHours = $null
    if (-not [string]::IsNullOrEmpty($expiration.duration)) { $durationHours = [math]::Round([System.Xml.XmlConvert]::ToTimeSpan([string]$expiration.duration).TotalHours, 2) }
    $creator = $request.createdBy.user
    $createdBy = @($creator.userPrincipalName, $creator.displayName, $creator.id, $request.createdBy.application.displayName) |
        Where-Object { -not [string]::IsNullOrEmpty($_) } | Select-Object -First 1
    $rows.Add([PSCustomObject]@{
        CreatedDateTime      = $created
        CreatedLocalTime     = $createdLocal
        OutsideBusinessHours = $outsideHours
        Action               = $request.action
        Status               = $request.status
        RoleName             = $roleDisplayName
        PrincipalDisplayName = $principal.displayName
        PrincipalUpn         = $principalUpn
        PrincipalType        = ([string]$principal.'@odata.type') -replace '^#microsoft\.graph\.', ''
        Justification        = $request.justification
        TicketNumber         = $request.ticketInfo.ticketNumber
        TicketSystem         = $request.ticketInfo.ticketSystem
        ScheduleStart        = ConvertTo-UtcDateTime -Value $request.scheduleInfo.startDateTime
        ScheduleEnd          = ConvertTo-UtcDateTime -Value $expiration.endDateTime
        DurationHours        = $durationHours
        DirectoryScopeId     = $request.directoryScopeId
        ApprovalId           = $request.approvalId
        CreatedBy            = $createdBy
    })
}

$sortedRows = @($rows | Sort-Object -Property CreatedDateTime -Descending)
if ($sortedRows.Count -gt 0) { $sortedRows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No PIM requests matched the selected filters; no CSV was written.' }

Write-Host ('PIM request summary (last {0} days): {1} requests -> {2}' -f $DaysBack, $sortedRows.Count, $OutputPath) -ForegroundColor Cyan
foreach ($property in @('Action', 'RoleName', 'PrincipalUpn')) {
    Write-Host ('  Top 10 by {0}:' -f $property)
    foreach ($group in ($sortedRows | Group-Object -Property $property | Sort-Object -Property Count -Descending | Select-Object -First 10)) {
        Write-Host ('    {0,-55} {1,5}' -f $group.Name, $group.Count)
    }
}
$outsideCount = @($sortedRows | Where-Object { $_.OutsideBusinessHours }).Count
if ($outsideCount -gt 0) {
    Write-Host ('  Outside business hours ({0:00}:00-{1:00}:00 local, Mon-Fri): {2}' -f $BusinessHoursStart, $BusinessHoursEnd, $outsideCount) -ForegroundColor Yellow
}
if ($PassThru) { $sortedRows }
#endregion Main
