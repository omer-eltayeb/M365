<#
.SYNOPSIS
    Reports Microsoft Entra entitlement management: access packages, their policies and who currently holds an assignment.
.DESCRIPTION
    Reads the access packages with their catalog (GET /identityGovernance/entitlementManagement/accessPackages?$expand=catalog),
    the assignment policies of each package (GET .../accessPackages/{id}/assignmentPolicies) and the delivered assignments
    (GET .../assignments?$expand=target,accessPackage,assignmentPolicy&$filter=state eq 'delivered'). One CSV row per
    assignment with package, catalog, policy, target, assignment and expiry dates and days until expiry is written to -OutputPath;
    the policy settings (target scope, expiration, approval, access review) go to <OutputPath>_Policies.csv.
.PARAMETER AccessPackageName
    Only packages whose display name matches this wildcard pattern, for example 'Contractor*'.
.PARAMETER ExpiringWithinDays
    Only assignments that expire within this many days (0 = all assignments). Default 0.
.PARAMETER OutputPath
    Path of the CSV report. Defaults to .\Reports\EntraEntitlementManagement_yyyyMMdd-HHmm.csv.
.PARAMETER PassThru
    Also emits the assignment objects to the pipeline.
.EXAMPLE
    PS> .\Get-EntraEntitlementManagementReport.ps1
    Exports every delivered access package assignment plus the policy table and prints the counts per package.
.EXAMPLE
    PS> .\Get-EntraEntitlementManagementReport.ps1 -ExpiringWithinDays 14 -AccessPackageName 'Contractor*' -PassThru
    Lists contractor assignments that expire within two weeks so the owners can be asked to extend or remove them.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : EntitlementManagement.Read.All (delegated); Global Reader or Identity Governance Administrator.
    Category    : Roles, governance & tenant policy
    Changes     : No
    Notes       : Requires Microsoft Entra ID Governance (or Entra ID P2 for the included features). Only assignments in state
                  'delivered' are reported; expired or failed deliveries are not included. Target users from connected
                  organizations appear with their external email address.
.LINK
    https://learn.microsoft.com/graph/api/entitlementmanagement-list-assignments
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [string]$AccessPackageName,

    [Parameter()]
    [ValidateRange(0, 3650)]
    [int]$ExpiringWithinDays = 0,

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
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('EntraEntitlementManagement_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$policiesPath = [System.IO.Path]::Combine($outputFolder, [System.IO.Path]::GetFileNameWithoutExtension($OutputPath) + '_Policies.csv')

try { Connect-GraphIfNeeded -Scopes @('EntitlementManagement.Read.All') }
catch { throw "Unable to connect to Microsoft Graph: $($_.Exception.Message)" }

$baseUri = 'https://graph.microsoft.com/v1.0/identityGovernance/entitlementManagement'
try { $packages = @(Invoke-GraphPaged -Uri ($baseUri + '/accessPackages?$expand=catalog') | Sort-Object -Property displayName) }
catch { throw "Failed to read access packages (requires Microsoft Entra ID Governance): $($_.Exception.Message)" }
if (-not [string]::IsNullOrWhiteSpace($AccessPackageName)) { $packages = @($packages | Where-Object { $_.displayName -like $AccessPackageName }) }
Write-Verbose "Loaded $($packages.Count) access packages."

$policyRows = New-Object -TypeName System.Collections.Generic.List[object]
$processed = 0
foreach ($package in $packages) {
    $processed++
    Write-Progress -Activity 'Reading access package policies' -Status $package.displayName -PercentComplete (($processed / $packages.Count) * 100)
    try {
        foreach ($policy in (Invoke-GraphPaged -Uri ('{0}/accessPackages/{1}/assignmentPolicies' -f $baseUri, $package.id))) {
            $expirationDays = $null
            if (-not [string]::IsNullOrEmpty($policy.expiration.duration)) { $expirationDays = [System.Xml.XmlConvert]::ToTimeSpan([string]$policy.expiration.duration).TotalDays }
            $approval = $policy.requestApprovalSettings
            $policyRows.Add([PSCustomObject]@{
                AccessPackage      = $package.displayName
                Catalog            = $package.catalog.displayName
                Policy             = $policy.displayName
                AllowedTargetScope = $policy.allowedTargetScope
                ExpirationType     = $policy.expiration.type
                ExpirationDays     = $expirationDays
                ExpirationDateTime = ConvertTo-UtcDateTime -Value $policy.expiration.endDateTime
                ApprovalRequired   = [bool]($approval.isApprovalRequiredForAdd -or $approval.isApprovalRequired)
                ReviewEnabled      = [bool]$policy.reviewSettings.isEnabled
                PackageHidden      = [bool]$package.isHidden
                PolicyId           = $policy.id
            })
        }
        Start-Sleep -Milliseconds 200
    }
    catch { Write-Warning ('Policies of access package "{0}" could not be read: {1}' -f $package.displayName, $_.Exception.Message) }
}
Write-Progress -Activity 'Reading access package policies' -Completed

try { $assignments = @(Invoke-GraphPaged -Uri ($baseUri + '/assignments?$expand=target,accessPackage,assignmentPolicy&$filter=state eq ''delivered''')) }
catch { throw "Failed to read access package assignments: $($_.Exception.Message)" }
Write-Verbose "Loaded $($assignments.Count) delivered assignments."

$now = [datetime]::UtcNow
$packageIds = @($packages | Select-Object -ExpandProperty id)
$rows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($assignment in $assignments) {
    if ($packageIds -notcontains [string]$assignment.accessPackage.id) { continue }
    $expiry = ConvertTo-UtcDateTime -Value $assignment.schedule.expiration.endDateTime
    $daysUntilExpiry = $null
    if ($null -ne $expiry) { $daysUntilExpiry = [math]::Round(($expiry - $now).TotalDays, 1) }
    if ($ExpiringWithinDays -gt 0 -and ($null -eq $daysUntilExpiry -or $daysUntilExpiry -gt $ExpiringWithinDays)) { continue }
    $target = $assignment.target
    $rows.Add([PSCustomObject]@{
        AccessPackage     = $assignment.accessPackage.displayName
        Catalog           = ($packages | Where-Object { $_.id -eq $assignment.accessPackage.id } | Select-Object -First 1).catalog.displayName
        Policy            = $assignment.assignmentPolicy.displayName
        TargetDisplayName = $target.displayName
        TargetUpn         = @($target.principalName, $target.email) | Where-Object { -not [string]::IsNullOrEmpty($_) } | Select-Object -First 1
        TargetType        = $target.subjectType
        State             = $assignment.state
        AssignedDateTime  = ConvertTo-UtcDateTime -Value $assignment.schedule.startDateTime
        ExpiryDateTime    = $expiry
        ExpirationType    = $assignment.schedule.expiration.type
        DaysUntilExpiry   = $daysUntilExpiry
        TargetObjectId    = $target.objectId
        AssignmentId      = $assignment.id
    })
}

$sortedRows = @($rows | Sort-Object -Property AccessPackage, TargetDisplayName)
if ($sortedRows.Count -gt 0) { $sortedRows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 }
else { Write-Warning 'No assignments matched the selected filters; no CSV was written.' }
if ($policyRows.Count -gt 0) { $policyRows | Export-Csv -Path $policiesPath -NoTypeInformation -Encoding UTF8 }

Write-Host ''
Write-Host 'Entitlement management summary (assignments / expiring within 30 days)' -ForegroundColor Cyan
foreach ($package in $packages) {
    $packageRows = @($sortedRows | Where-Object { $_.AccessPackage -eq $package.displayName })
    $expiringSoon = @($packageRows | Where-Object { $null -ne $_.DaysUntilExpiry -and $_.DaysUntilExpiry -le 30 }).Count
    Write-Host ('  {0,-50} {1,5} / {2,-5} {3}' -f $package.displayName, $packageRows.Count, $expiringSoon, $(if ($package.isHidden) { '(hidden)' } else { '' }))
}
Write-Host ('  Assignments exported : {0} -> {1}' -f $sortedRows.Count, $OutputPath)
Write-Host ('  Policies exported    : {0} -> {1}' -f $policyRows.Count, $policiesPath)
$noApproval = @($policyRows | Where-Object { -not $_.ApprovalRequired -and $_.AllowedTargetScope -in @('allExternalUsers', 'allConfiguredConnectedOrganizationUsers') })
if ($noApproval.Count -gt 0) {
    Write-Host ('  Policies open to external users without approval: {0}' -f $noApproval.Count) -ForegroundColor Yellow
}

if ($PassThru) { $sortedRows }
#endregion Main
