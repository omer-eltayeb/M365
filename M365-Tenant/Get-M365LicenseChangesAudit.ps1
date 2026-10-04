<#
.SYNOPSIS
    Reports who added or removed which licenses for which users, from the Microsoft Entra directory audit log.
.DESCRIPTION
    Queries /auditLogs/directoryAudits for 'Change user license' activities in the last -DaysBack days (optionally for one
    target user) and parses the AssignedLicense modified property of the target: old and new values are JSON arrays of
    strings such as "[SkuName=SPE_E3, AccountId=..., SkuId=<guid>, DisabledPlans=[]]", from which the added and removed
    SKU ids are derived and mapped to part numbers via /subscribedSkus. The actor is the signed-in user, an application or
    the group-based licensing service. Outputs one row per audit entry and prints totals by actor, by SKU and per day.
.PARAMETER DaysBack
    Number of days to look back (1-30; the directory audit log keeps 30 days with Microsoft Entra ID P1/P2). Default 30.
.PARAMETER UserPrincipalName
    Only return license changes made to this target user.
.PARAMETER OutputPath
    Path of the CSV file. Defaults to .\Reports\M365LicenseChangesAudit_<timestamp>.csv.
.PARAMETER PassThru
    Also emit the row objects to the pipeline.
.EXAMPLE
    PS> .\Get-M365LicenseChangesAudit.ps1 -DaysBack 7
    Exports every license assignment change of the last week and shows who made them and which SKUs moved most.
.EXAMPLE
    PS> .\Get-M365LicenseChangesAudit.ps1 -UserPrincipalName jdoe@contoso.com -PassThru | Format-Table ActivityDateTime, Actor, SkusAdded, SkusRemoved
    Shows the license history of one user for the last 30 days in the console.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : AuditLog.Read.All, Organization.Read.All (delegated); some tenants also need Directory.Read.All for directoryAudits.
                  Global Reader, Reports Reader or Security Reader can run it.
    Category    : Licensing
    Changes     : No
    Notes       : Group-based licensing changes are logged with the actor 'Microsoft Azure AD Group-Based Licensing' (ActorType
                  GroupBasedLicensing). Entries whose SKU set did not change (only disabled plans changed) are flagged
                  PlanChangeOnly. Audit events can take up to an hour to appear. All date/time values are UTC.
.LINK
    https://learn.microsoft.com/graph/api/directoryaudit-list
.LINK
    https://learn.microsoft.com/graph/api/resources/directoryaudit
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 30)]
    [int]$DaysBack = 30,

    [Parameter()]
    [string]$UserPrincipalName,

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
    <# Normalises a Graph date value (ISO 8601 string or [datetime]) to a UTC [datetime]; $null when empty or unparseable. #>
    param([Parameter()][AllowNull()]$Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    if ($Value -is [datetime]) { if ($Value.Kind -eq 'Local') { return $Value.ToUniversalTime() }; return [datetime]::SpecifyKind($Value, 'Utc') }
    $parsed = [datetime]::MinValue
    if ([datetime]::TryParse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, 'AssumeUniversal, AdjustToUniversal', [ref]$parsed)) { return $parsed }
    return $null
}

function Get-AuditSkuIds {
    <# Extracts the distinct SKU ids from an AssignedLicense audit value (JSON array of "[SkuName=..., SkuId=<guid>, ...]" strings). #>
    param([Parameter()][AllowNull()]$Value)
    if ([string]::IsNullOrWhiteSpace([string]$Value)) { return @() }
    return @([regex]::Matches([string]$Value, 'SkuId=([0-9a-fA-F-]{36})') | ForEach-Object { $_.Groups[1].Value.ToLower() } | Sort-Object -Unique)
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('M365LicenseChangesAudit_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
try { Connect-GraphIfNeeded -Scopes @('AuditLog.Read.All', 'Organization.Read.All') }
catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }
try { $skus = @(Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/subscribedSkus?$select=skuId,skuPartNumber') }
catch { throw "Failed to read subscribed SKUs: $($_.Exception.Message)" }
$skuNameById = @{}
foreach ($sku in $skus) { $skuNameById[([string]$sku.skuId).ToLower()] = [string]$sku.skuPartNumber }

$since = [datetime]::UtcNow.AddDays(-$DaysBack).ToString('yyyy-MM-ddTHH:mm:ssZ')
$filter = "activityDateTime ge $since and activityDisplayName eq 'Change user license'"
if (-not [string]::IsNullOrWhiteSpace($UserPrincipalName)) {
    $filter += " and targetResources/any(t:t/userPrincipalName eq '{0}')" -f $UserPrincipalName.Replace("'", "''")
}
Write-Verbose "Querying directory audits: $filter"
try { $audits = @(Invoke-GraphPaged -Uri ('https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$filter=' + $filter)) }
catch { throw "Failed to read the directory audit log: $($_.Exception.Message)" }

$rows = New-Object -TypeName System.Collections.Generic.List[object]
$counter = 0
foreach ($entry in $audits) {
    $counter++
    if ($counter % 100 -eq 0) { Write-Progress -Activity 'Parsing license change events' -Status "$counter of $($audits.Count)" -PercentComplete ([int](($counter / $audits.Count) * 100)) }
    $target = $entry.targetResources | Where-Object { $_.type -eq 'User' } | Select-Object -First 1
    if ($null -eq $target) { $target = $entry.targetResources | Select-Object -First 1 }
    $licenseProperty = $target.modifiedProperties | Where-Object { $_.displayName -eq 'AssignedLicense' } | Select-Object -First 1
    $oldIds = @(Get-AuditSkuIds -Value $licenseProperty.oldValue)
    $newIds = @(Get-AuditSkuIds -Value $licenseProperty.newValue)
    $added = @($newIds | Where-Object { $oldIds -notcontains $_ } | ForEach-Object { if ($skuNameById.ContainsKey($_)) { $skuNameById[$_] } else { $_ } })
    $removed = @($oldIds | Where-Object { $newIds -notcontains $_ } | ForEach-Object { if ($skuNameById.ContainsKey($_)) { $skuNameById[$_] } else { $_ } })
    $actor = ''
    $actorType = 'Unknown'
    if ($null -ne $entry.initiatedBy.user) {
        $actor = [string]$entry.initiatedBy.user.userPrincipalName
        if ([string]::IsNullOrEmpty($actor)) { $actor = [string]$entry.initiatedBy.user.displayName }
        $actorType = 'User'
    }
    elseif ($null -ne $entry.initiatedBy.app) {
        $actor = [string]$entry.initiatedBy.app.displayName
        $actorType = 'Application'
        if ($actor -like '*Group-Based Licensing*') { $actorType = 'GroupBasedLicensing' }
    }
    $rows.Add([PSCustomObject]@{
            ActivityDateTime        = (ConvertTo-UtcDateTime -Value $entry.activityDateTime)
            TargetUserPrincipalName = $target.userPrincipalName
            TargetUserId            = $target.id
            Actor                   = $actor
            ActorType               = $actorType
            SkusAdded               = ($added -join ';')
            SkusRemoved             = ($removed -join ';')
            AddedCount              = $added.Count
            RemovedCount            = $removed.Count
            PlanChangeOnly          = ($null -ne $licenseProperty -and $added.Count -eq 0 -and $removed.Count -eq 0)
            Result                  = $entry.result
            ResultReason            = $entry.resultReason
            CorrelationId           = $entry.correlationId
        })
}
Write-Progress -Activity 'Parsing license change events' -Completed
$output = @($rows | Sort-Object -Property ActivityDateTime -Descending)
$output | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host ('License change audit - last {0} days' -f $DaysBack) -ForegroundColor Cyan
Write-Host ('  Events / failed              : {0} / {1}' -f $output.Count, @($output | Where-Object { $_.Result -ne 'success' }).Count)
Write-Host ('  Assignments added / removed  : {0} / {1}' -f [int]($output | Measure-Object -Property AddedCount -Sum).Sum, [int]($output | Measure-Object -Property RemovedCount -Sum).Sum)
Write-Host '  By actor                     :'
foreach ($actorGroup in ($output | Group-Object -Property Actor | Sort-Object -Property Count -Descending | Select-Object -First 10)) {
    Write-Host ('    {0,-50} {1,6}' -f $actorGroup.Name, $actorGroup.Count)
}
Write-Host '  By SKU (added / removed)     :'
$skuNames = @($output | ForEach-Object { ($_.SkusAdded -split ';') + ($_.SkusRemoved -split ';') } | Where-Object { -not [string]::IsNullOrEmpty($_) } | Sort-Object -Unique)
foreach ($skuName in $skuNames) {
    $addCount = @($output | Where-Object { ($_.SkusAdded -split ';') -contains $skuName }).Count
    $removeCount = @($output | Where-Object { ($_.SkusRemoved -split ';') -contains $skuName }).Count
    Write-Host ('    {0,-50} {1,6} / {2,6}' -f $skuName, $addCount, $removeCount)
}
Write-Host '  Per day (added / removed)    :'
foreach ($day in ($output | Group-Object -Property { '{0:yyyy-MM-dd}' -f $_.ActivityDateTime } | Sort-Object -Property Name)) {
    Write-Host ('    {0,-50} {1,6} / {2,6}' -f $day.Name, [int]($day.Group | Measure-Object -Property AddedCount -Sum).Sum, [int]($day.Group | Measure-Object -Property RemovedCount -Sum).Sum)
}
Write-Host ('  CSV                          : {0}' -f $OutputPath)
if ($PassThru) { $output }
#endregion Main
