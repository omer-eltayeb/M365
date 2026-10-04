<#
.SYNOPSIS
    Reports every Windows 365 Cloud PC with its status, service plan, provisioning policy and optional connectivity health, and flags Cloud PCs needing attention.
.DESCRIPTION
    Reads Cloud PCs from Microsoft Graph v1.0 (/deviceManagement/virtualEndpoint/cloudPCs) and provisioning policies with their
    assignments (/virtualEndpoint/provisioningPolicies?$expand=assignments), joins the policy's join type and single sign-on
    setting to each Cloud PC and flags Cloud PCs that are in grace period, failed or not provisioned. With -IncludeConnectivity
    the beta endpoint adds last login, connectivity result and last remote action. Exports to CSV and prints a status/plan summary.
.PARAMETER IncludeConnectivity
    Also read lastLoginResult, connectivityResult and lastRemoteActionResult from the beta endpoint (one extra paged call).
.PARAMETER OnlyAttention
    Report only Cloud PCs that are in grace period, failed or not provisioned.
.PARAMETER OutputPath
    CSV file to create. Defaults to .\Reports\IntuneCloudPCReport_yyyyMMdd-HHmm.csv; the folder is created when missing.
.PARAMETER PassThru
    Also emit the report objects to the pipeline.
.EXAMPLE
    PS> .\Get-IntuneCloudPCReport.ps1
    Lists every Cloud PC with status, plan and policy details and prints the status and plan distribution.
.EXAMPLE
    PS> .\Get-IntuneCloudPCReport.ps1 -IncludeConnectivity -PassThru | Where-Object { $_.Connectivity -ne 'available' -or $_.NeedsAttention }
    Finds Cloud PCs that are unhealthy, unreachable, failed or about to be deprovisioned.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : CloudPC.Read.All (delegated) plus an Intune RBAC role such as Cloud PC Reader or Read Only Operator
    Category    : Reporting & platform insights
    Changes     : No
    Notes       : Requires Windows 365 Enterprise or Frontline licences; Windows 365 Business Cloud PCs appear without a policy.
                  A Cloud PC enters the 7-day grace period when its licence is removed or reassigned and is deprovisioned afterwards.
                  Connectivity, last login and last remote action exist only on the beta endpoint (may change without notice). Dates are UTC.
.LINK
    https://learn.microsoft.com/graph/api/virtualendpoint-list-cloudpcs
.LINK
    https://learn.microsoft.com/graph/api/virtualendpoint-list-provisioningpolicies
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$IncludeConnectivity,

    [Parameter()]
    [switch]$OnlyAttention,

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
    <# Converts a Graph date value (string or DateTime) to a UTC [datetime]; $null for empty values or the 0001-01-01 placeholder. #>
    param([object]$Value)
    if ([string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    try { $parsed = ([datetime]$Value).ToUniversalTime() } catch { return $null }
    if ($parsed.Year -le 1) { return $null }
    return $parsed
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('IntuneCloudPCReport_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}

try { Connect-GraphIfNeeded -Scopes @('CloudPC.Read.All') } catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }

$v1 = 'https://graph.microsoft.com/v1.0/deviceManagement/virtualEndpoint'
$cloudPcUri = $v1 + '/cloudPCs?$select=id,displayName,userPrincipalName,status,servicePlanName,provisioningPolicyId,provisioningPolicyName,' +
    'imageDisplayName,managedDeviceName,lastModifiedDateTime,gracePeriodEndDateTime,provisioningType'
try { $cloudPcs = @(Invoke-GraphPaged -Uri $cloudPcUri) } catch { throw "Failed to retrieve Cloud PCs: $($_.Exception.Message)" }
Write-Verbose ('{0} Cloud PCs retrieved.' -f $cloudPcs.Count)

# Policies are read once and joined by id so each row shows join type, image and SSO without a per-Cloud PC call.
$policies = @()
try { $policies = @(Invoke-GraphPaged -Uri ($v1 + '/provisioningPolicies?$expand=assignments')) }
catch { Write-Warning ('Could not read provisioning policies: {0}' -f $_.Exception.Message) }
$policyById = @{}
foreach ($policy in $policies) {
    $joinTypes = @($policy.domainJoinConfigurations | ForEach-Object { [string]$_.domainJoinType } | Select-Object -Unique)
    $policyById[[string]$policy.id] = [PSCustomObject]@{ Name = $policy.displayName; Image = $policy.imageDisplayName; JoinType = ($joinTypes -join '/')
        SingleSignOn = $policy.enableSingleSignOn; Assignments = @($policy.assignments | Where-Object { $null -ne $_ }).Count; CloudPCs = 0 }
}

$healthById = @{}
if ($IncludeConnectivity) {
    # beta: lastLoginResult, connectivityResult and lastRemoteActionResult are not exposed in v1.0 and are only returned when selected explicitly.
    $betaUri = 'https://graph.microsoft.com/beta/deviceManagement/virtualEndpoint/cloudPCs?$select=id,lastLoginResult,connectivityResult,lastRemoteActionResult'
    try { foreach ($item in @(Invoke-GraphPaged -Uri $betaUri)) { $healthById[[string]$item.id] = $item } }
    catch { Write-Warning ('Could not read connectivity details: {0}' -f $_.Exception.Message) }
}

$attentionStates = @('inGracePeriod', 'failed', 'notProvisioned')
$report = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($cloudPc in $cloudPcs) {
    $needsAttention = $attentionStates -contains [string]$cloudPc.status
    if ($OnlyAttention -and -not $needsAttention) { continue }
    $policy = $policyById[[string]$cloudPc.provisioningPolicyId]
    if ($null -ne $policy) { $policy.CloudPCs++ }
    $health = $healthById[[string]$cloudPc.id]
    $lastAction = $null
    if ($null -ne $health -and $null -ne $health.lastRemoteActionResult) { $lastAction = '{0}: {1}' -f $health.lastRemoteActionResult.actionName, $health.lastRemoteActionResult.actionState }

    $report.Add([PSCustomObject]@{
            CloudPCName         = $cloudPc.displayName
            UserPrincipalName   = $cloudPc.userPrincipalName
            Status              = $cloudPc.status
            NeedsAttention      = $needsAttention
            ServicePlan         = $cloudPc.servicePlanName
            ProvisioningPolicy  = $cloudPc.provisioningPolicyName
            ProvisioningType    = $cloudPc.provisioningType
            JoinType            = $policy.JoinType
            SingleSignOn        = $policy.SingleSignOn
            Image               = $cloudPc.imageDisplayName
            ManagedDeviceName   = $cloudPc.managedDeviceName
            GracePeriodEnd      = ConvertTo-UtcDateTime -Value $cloudPc.gracePeriodEndDateTime
            LastModified        = ConvertTo-UtcDateTime -Value $cloudPc.lastModifiedDateTime
            Connectivity        = $health.connectivityResult.overallResult
            ConnectivityUpdated = ConvertTo-UtcDateTime -Value $health.connectivityResult.updatedDateTime
            LastLogin           = ConvertTo-UtcDateTime -Value $health.lastLoginResult.time
            LastRemoteAction    = $lastAction
            CloudPcId           = $cloudPc.id
        })
}

if ($report.Count -gt 0) {
    $report | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host ('Report written to {0}' -f $OutputPath) -ForegroundColor Green
}
else { Write-Warning 'No Cloud PCs matched the selection; no CSV file was written.' }

Write-Host ('Cloud PCs reported : {0}  (needing attention: {1})' -f $report.Count, @($report | Where-Object { $_.NeedsAttention }).Count) -ForegroundColor Cyan
Write-Host 'By status:' -ForegroundColor Cyan
foreach ($group in ($report | Group-Object -Property Status | Sort-Object -Property Count -Descending)) {
    $colour = 'Green'; if ($attentionStates -contains $group.Name) { $colour = 'Red' }
    Write-Host ('  {0,-28} {1,6}' -f $group.Name, $group.Count) -ForegroundColor $colour
}
Write-Host 'By service plan:' -ForegroundColor Cyan
foreach ($group in ($report | Group-Object -Property ServicePlan | Sort-Object -Property Count -Descending)) {
    Write-Host ('  {0,-60} {1,6}' -f $group.Name, $group.Count)
}
if ($policyById.Count -gt 0) {
    Write-Host 'Provisioning policies (name, join type, SSO, assignments, Cloud PCs):' -ForegroundColor Cyan
    foreach ($policy in ($policyById.Values | Sort-Object -Property Name)) {
        Write-Host ('  {0,-40} {1,-18} SSO={2,-5} assignments={3,-3} cloudPCs={4}' -f $policy.Name, $policy.JoinType, $policy.SingleSignOn, $policy.Assignments, $policy.CloudPCs)
    }
}
if ($IncludeConnectivity) {
    $unavailable = @($report | Where-Object { $null -ne $_.Connectivity -and $_.Connectivity -ne 'available' }).Count
    Write-Host ('Connectivity not "available": {0}' -f $unavailable) -ForegroundColor Yellow
}

if ($PassThru) { $report }
#endregion Main
