<#
.SYNOPSIS
    Per-policy compliance status summary (compliant, non-compliant, error, conflict, pending) for every Intune compliance policy.
.DESCRIPTION
    Lists all compliance policies (v1.0 /deviceManagement/deviceCompliancePolicies), derives the platform from
    the policy type, counts the assignments and reads the device status overview of each policy
    (/deviceCompliancePolicies/{id}/deviceStatusOverview). With -IncludeDeviceStatuses the per-device status
    rows (/deviceCompliancePolicies/{id}/deviceStatuses) are written to a second CSV named <OutputPath>_Devices.csv.
    A console summary of the policies with the most non-compliant devices is printed.
.PARAMETER PolicyName
    Wildcard pattern (for example 'Windows*') applied to the policy display name.
.PARAMETER IncludeDeviceStatuses
    Also download the per-device status of every policy into <OutputPath>_Devices.csv (one extra Graph call per policy).
.PARAMETER OutputPath
    CSV file to create. Defaults to .\Reports\IntuneCompliancePolicyStatus_yyyyMMdd-HHmm.csv; the folder is created when missing.
.PARAMETER PassThru
    Also emit the summary rows to the pipeline.
.EXAMPLE
    PS> .\Get-IntuneCompliancePolicyStatusSummary.ps1
    Exports one row per compliance policy with its status counts and prints the policies with the most failures.
.EXAMPLE
    PS> .\Get-IntuneCompliancePolicyStatusSummary.ps1 -PolicyName 'iOS*' -IncludeDeviceStatuses -OutputPath C:\Temp\iOSCompliance.csv
    Writes the summary to iOSCompliance.csv and every device status of the iOS policies to iOSCompliance_Devices.csv.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : DeviceManagementConfiguration.Read.All (delegated) plus an Intune RBAC role such as Read Only Operator
    Category    : Compliance, configuration & RBAC
    Changes     : No
    Notes       : Uses the v1.0 endpoint only. The status overview is an aggregate that Intune refreshes periodically
                  (see LastStatusUpdate), so counts can lag the device list by a few hours. The per-device status
                  collection can contain thousands of rows per policy in large tenants. All date/time values are UTC.
.LINK
    https://learn.microsoft.com/graph/api/intune-deviceconfig-devicecompliancepolicy-list
.LINK
    https://learn.microsoft.com/graph/api/intune-deviceconfig-devicecompliancedeviceoverview-get
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [string]$PolicyName,

    [Parameter()]
    [switch]$IncludeDeviceStatuses,

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
    <# Normalises a Graph date value (string or DateTime) to a UTC [datetime]; returns $null for empty or 0001-01-01 placeholders. #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [object]$Value
    )
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    try { $parsed = [datetime]$Value } catch { return $null }
    if ($parsed.Year -le 1) { return $null }
    return $parsed.ToUniversalTime()
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('IntuneCompliancePolicyStatus_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try {
    Connect-GraphIfNeeded -Scopes @('DeviceManagementConfiguration.Read.All')
}
catch {
    throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
}

$graphV1 = 'https://graph.microsoft.com/v1.0/deviceManagement'
try {
    $policies = @(Invoke-GraphPaged -Uri ($graphV1 + '/deviceCompliancePolicies?$select=id,displayName,createdDateTime,lastModifiedDateTime,version'))
}
catch {
    throw "Failed to list compliance policies: $($_.Exception.Message)"
}
if (-not [string]::IsNullOrWhiteSpace($PolicyName)) {
    $policies = @($policies | Where-Object { $_.displayName -like $PolicyName })
}
Write-Verbose ('{0} compliance policies to summarise.' -f $policies.Count)

# The policy type (e.g. windows10CompliancePolicy) is the only reliable platform indicator on v1.0.
$platformNames = @{
    windows10 = 'Windows 10/11'; windows81 = 'Windows 8.1'; windowsPhone81 = 'Windows Phone 8.1'; iOS = 'iOS/iPadOS'
    macOS = 'macOS'; android = 'Android device administrator'; androidWorkProfile = 'Android Enterprise (personally-owned work profile)'
    androidDeviceOwner = 'Android Enterprise (corporate-owned)'; aospDeviceOwner = 'Android (AOSP)'; defaultDevice = 'Built-in default policy'
}

$report = New-Object -TypeName System.Collections.Generic.List[object]
$deviceRows = New-Object -TypeName System.Collections.Generic.List[object]
$failed = 0
$index = 0
foreach ($policy in $policies) {
    $index++
    Write-Progress -Activity 'Reading compliance policy status' -Status ('{0} of {1}: {2}' -f $index, $policies.Count, $policy.displayName) -PercentComplete ([int](($index / $policies.Count) * 100))
    $typeKey = ([string]$policy.'@odata.type' -replace '^#microsoft\.graph\.', '') -replace 'CompliancePolicy$', ''
    $platform = $typeKey
    if ($platformNames.ContainsKey($typeKey)) { $platform = $platformNames[$typeKey] }

    try {
        $overview = Invoke-MgGraphRequest -Method GET -Uri ('{0}/deviceCompliancePolicies/{1}/deviceStatusOverview' -f $graphV1, $policy.id) -OutputType PSObject -ErrorAction Stop
        $assignments = @(Invoke-GraphPaged -Uri ('{0}/deviceCompliancePolicies/{1}/assignments' -f $graphV1, $policy.id))
    }
    catch {
        $failed++
        Write-Warning ("Could not read status for policy '{0}' ({1}): {2}" -f $policy.displayName, $policy.id, $_.Exception.Message)
        continue
    }
    $targetTypes = @($assignments | ForEach-Object { [string]$_.target.'@odata.type' })

    $report.Add([PSCustomObject]@{
            PolicyName       = $policy.displayName
            Platform         = $platform
            AssignmentCount  = $assignments.Count
            AllUsers         = ($targetTypes -contains '#microsoft.graph.allLicensedUsersAssignmentTarget')
            AllDevices       = ($targetTypes -contains '#microsoft.graph.allDevicesAssignmentTarget')
            IncludedGroups   = @($targetTypes | Where-Object { $_ -eq '#microsoft.graph.groupAssignmentTarget' }).Count
            ExcludedGroups   = @($targetTypes | Where-Object { $_ -eq '#microsoft.graph.exclusionGroupAssignmentTarget' }).Count
            Compliant        = $overview.successCount
            NonCompliant     = $overview.failedCount
            Error            = $overview.errorCount
            Conflict         = $overview.conflictCount
            Pending          = $overview.pendingCount
            NotApplicable    = $overview.notApplicableCount
            TotalDevices     = [int]$overview.successCount + [int]$overview.failedCount + [int]$overview.errorCount + [int]$overview.conflictCount + [int]$overview.pendingCount + [int]$overview.notApplicableCount
            LastStatusUpdate = ConvertTo-UtcDateTime -Value $overview.lastUpdateDateTime
            LastModified     = ConvertTo-UtcDateTime -Value $policy.lastModifiedDateTime
            Version          = $policy.version
            PolicyId         = $policy.id
        })

    if ($IncludeDeviceStatuses) {
        try {
            foreach ($status in @(Invoke-GraphPaged -Uri ('{0}/deviceCompliancePolicies/{1}/deviceStatuses' -f $graphV1, $policy.id))) {
                $deviceRows.Add([PSCustomObject]@{
                        PolicyName           = $policy.displayName
                        Platform             = $platform
                        DeviceName           = $status.deviceDisplayName
                        UserName             = $status.userName
                        UserPrincipalName    = $status.userPrincipalName
                        DeviceModel          = $status.deviceModel
                        Status               = $status.status
                        LastReportedDateTime = ConvertTo-UtcDateTime -Value $status.lastReportedDateTime
                        GracePeriodExpires   = ConvertTo-UtcDateTime -Value $status.complianceGracePeriodExpirationDateTime
                        PolicyId             = $policy.id
                    })
            }
        }
        catch {
            Write-Warning ("Could not read device statuses for policy '{0}': {1}" -f $policy.displayName, $_.Exception.Message)
        }
    }
    Start-Sleep -Milliseconds 200
}
Write-Progress -Activity 'Reading compliance policy status' -Completed

if ($report.Count -gt 0) {
    $report | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host ('Report written to {0}' -f $OutputPath) -ForegroundColor Green
}
else {
    Write-Warning 'No compliance policies matched the criteria; no CSV file was written.'
}
if ($IncludeDeviceStatuses -and $deviceRows.Count -gt 0) {
    $devicesPath = ($OutputPath -replace '\.csv$', '') + '_Devices.csv'
    $deviceRows | Export-Csv -Path $devicesPath -NoTypeInformation -Encoding UTF8
    Write-Host ('Device statuses written to {0} ({1} rows)' -f $devicesPath, $deviceRows.Count) -ForegroundColor Green
}

Write-Host ''
Write-Host ('Compliance policies summarised : {0}' -f $report.Count) -ForegroundColor Cyan
Write-Host ('Policies that could not be read: {0}' -f $failed) -ForegroundColor Cyan
Write-Host ('Compliant device evaluations   : {0}' -f (($report | Measure-Object -Property Compliant -Sum).Sum)) -ForegroundColor Green
Write-Host ('Non-compliant evaluations      : {0}' -f (($report | Measure-Object -Property NonCompliant -Sum).Sum)) -ForegroundColor Yellow
Write-Host 'Policies with the most non-compliant devices:' -ForegroundColor Cyan
foreach ($row in ($report | Where-Object { $_.NonCompliant -gt 0 } | Sort-Object -Property NonCompliant -Descending | Select-Object -First 10)) {
    Write-Host ('  {0,-60} {1,6} non-compliant, {2,5} error, {3,5} conflict' -f $row.PolicyName, $row.NonCompliant, $row.Error, $row.Conflict) -ForegroundColor Yellow
}

if ($PassThru) {
    $report
}
#endregion Main
