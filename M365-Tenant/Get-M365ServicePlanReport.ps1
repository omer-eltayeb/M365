<#
.SYNOPSIS
    Reports the service plans inside every subscribed SKU and, per user, which plans are disabled or not provisioned.
.DESCRIPTION
    Reads /subscribedSkus and writes one row per SKU and service plan (name, id, provisioningStatus Success / PendingInput /
    PendingActivation / Disabled, appliesTo) to <OutputPath base>_SkuPlans.csv. With -IncludeUsers (or -ServicePlanName) it
    also reads every licensed user from /users with assignedLicenses and assignedPlans and writes one row per user and SKU to
    OutputPath: the plans disabled in that assignment (disabledPlans mapped to names) and the plans whose capabilityStatus is
    not Enabled (Warning, Suspended, Deleted, LockedOut). -ServicePlanName keeps only users who have that plan enabled through
    at least one SKU, or with -ShowUsersWithoutPlan only those who do not.
.PARAMETER IncludeUsers
    Also export the per-user view (one paged query, no per-user calls).
.PARAMETER ServicePlanName
    Service plan to look for, for example INTUNE_A, EXCHANGE_S_ENTERPRISE, MCOSTANDARD, TEAMS1, AAD_PREMIUM or OFFICESUBSCRIPTION.
.PARAMETER ShowUsersWithoutPlan
    With -ServicePlanName, list the licensed users who do NOT have that plan enabled instead of those who do.
.PARAMETER OutputPath
    Path of the user CSV. Defaults to .\Reports\M365ServicePlans_<timestamp>.csv; the SKU/plan matrix uses the same base plus _SkuPlans.
.PARAMETER PassThru
    Also emit the SKU/plan rows (and, when requested, the user rows) to the pipeline.
.EXAMPLE
    PS> .\Get-M365ServicePlanReport.ps1
    Exports the SKU/plan matrix and prints plans that are not fully provisioned (PendingInput usually needs admin action).
.EXAMPLE
    PS> .\Get-M365ServicePlanReport.ps1 -ServicePlanName INTUNE_A -ShowUsersWithoutPlan -OutputPath C:\Temp\NoIntune.csv
    Lists every licensed user whose licenses do not give them an enabled Intune plan - useful before an enrollment rollout.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : Organization.Read.All, User.Read.All (delegated); Global Reader or License Administrator.
    Category    : Licensing
    Changes     : No
    Notes       : assignedPlans keeps historical entries (capabilityStatus Deleted) for licenses removed earlier, so only plans of
                  SKUs the user currently holds are evaluated; a plan disabled in the assignment is reported as disabled, not as
                  an issue. Plans with appliesTo = Company are tenant-wide and skipped in the user view.
.LINK
    https://learn.microsoft.com/graph/api/resources/serviceplaninfo
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$IncludeUsers,

    [Parameter()]
    [string]$ServicePlanName,

    [Parameter()]
    [switch]$ShowUsersWithoutPlan,

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
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('M365ServicePlans_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
# Path.Combine tolerates an empty folder (bare file name in -OutputPath) where Join-Path would throw.
$skuPlansPath = [System.IO.Path]::Combine([string]$outputFolder, ('{0}_SkuPlans.csv' -f [System.IO.Path]::GetFileNameWithoutExtension($OutputPath)))
$includeUsers = $IncludeUsers -or -not [string]::IsNullOrWhiteSpace($ServicePlanName)
try { Connect-GraphIfNeeded -Scopes @('Organization.Read.All', 'User.Read.All') }
catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }
try { $skus = @(Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/subscribedSkus?$select=skuId,skuPartNumber,prepaidUnits,consumedUnits,servicePlans') }
catch { throw "Failed to read subscribed SKUs: $($_.Exception.Message)" }
$skuById = @{}
$skuPlanRows = New-Object -TypeName System.Collections.Generic.List[object]
foreach ($sku in $skus) {
    $skuById[[string]$sku.skuId] = $sku
    foreach ($plan in @($sku.servicePlans)) {
        $skuPlanRows.Add([PSCustomObject]@{
                SkuPartNumber      = $sku.skuPartNumber
                SkuId              = $sku.skuId
                ServicePlanName    = $plan.servicePlanName
                ServicePlanId      = $plan.servicePlanId
                ProvisioningStatus = $plan.provisioningStatus
                AppliesTo          = $plan.appliesTo
                SkuEnabledUnits    = [int]$sku.prepaidUnits.enabled
            })
    }
}
$skuPlanOutput = @($skuPlanRows | Sort-Object -Property SkuPartNumber, ServicePlanName)
$skuPlanOutput | Export-Csv -Path $skuPlansPath -NoTypeInformation -Encoding UTF8
if ($includeUsers -and -not [string]::IsNullOrWhiteSpace($ServicePlanName) -and $skuPlanOutput.ServicePlanName -notcontains $ServicePlanName) {
    throw "Service plan '$ServicePlanName' does not exist in any subscribed SKU (see $skuPlansPath for valid names)."
}
$userRows = New-Object -TypeName System.Collections.Generic.List[object]
if ($includeUsers) {
    try {
        $userSelect = 'id,displayName,userPrincipalName,accountEnabled,assignedLicenses,assignedPlans'
        $usersUri = 'https://graph.microsoft.com/v1.0/users?$filter=assignedLicenses/$count ne 0&$count=true&$top=999&$select=' + $userSelect
        $users = @(Invoke-GraphPaged -Uri $usersUri -Headers @{ ConsistencyLevel = 'eventual' })
    }
    catch { throw "Failed to list licensed users: $($_.Exception.Message)" }
    $counter = 0
    foreach ($user in $users) {
        $counter++
        if ($counter % 100 -eq 0) { Write-Progress -Activity 'Evaluating service plans per user' -Status "$counter of $($users.Count)" -PercentComplete ([int](($counter / $users.Count) * 100)) }
        $planStatus = @{}
        foreach ($assignedPlan in @($user.assignedPlans)) { $planStatus[[string]$assignedPlan.servicePlanId] = [string]$assignedPlan.capabilityStatus }
        $planEnabled = $false
        $rowsForUser = @()
        foreach ($license in @($user.assignedLicenses)) {
            $sku = $skuById[[string]$license.skuId]
            if ($null -eq $sku) { continue }
            $disabledIds = @($license.disabledPlans | ForEach-Object { [string]$_ })
            $disabledNames = @(); $issues = @()
            foreach ($plan in @($sku.servicePlans | Where-Object { $_.appliesTo -eq 'User' })) {
                $planId = [string]$plan.servicePlanId
                if ($disabledIds -contains $planId) { $disabledNames += [string]$plan.servicePlanName; continue }
                if ($plan.servicePlanName -eq $ServicePlanName) { $planEnabled = $true }
                if ($planStatus.ContainsKey($planId) -and $planStatus[$planId] -ne 'Enabled') { $issues += ('{0}:{1}' -f $plan.servicePlanName, $planStatus[$planId]) }
            }
            $rowsForUser += [PSCustomObject]@{
                UserPrincipalName   = $user.userPrincipalName
                DisplayName         = $user.displayName
                AccountEnabled      = [bool]$user.accountEnabled
                Sku                 = $sku.skuPartNumber
                DisabledPlanCount   = $disabledNames.Count
                DisabledPlans       = (($disabledNames | Sort-Object) -join ';')
                PlansWithIssues     = (($issues | Sort-Object) -join ';')
                FilteredPlan        = $ServicePlanName
                FilteredPlanEnabled = $null
            }
        }
        if (-not [string]::IsNullOrWhiteSpace($ServicePlanName)) {
            # Default keeps users who have the plan enabled; -ShowUsersWithoutPlan inverts the selection.
            if ($planEnabled -eq [bool]$ShowUsersWithoutPlan) { continue }
            foreach ($userRow in $rowsForUser) { $userRow.FilteredPlanEnabled = $planEnabled }
        }
        foreach ($userRow in $rowsForUser) { $userRows.Add($userRow) }
    }
    Write-Progress -Activity 'Evaluating service plans per user' -Completed
    $userRows | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
}

$pendingPlans = @($skuPlanOutput | Where-Object { $_.ProvisioningStatus -ne 'Success' -and $_.SkuEnabledUnits -gt 0 })
Write-Host 'Service plan summary' -ForegroundColor Cyan
Write-Host ('  SKUs / service plans         : {0} / {1}' -f $skus.Count, $skuPlanOutput.Count)
Write-Host ('  Plans not fully provisioned  : {0}' -f $pendingPlans.Count) -ForegroundColor Yellow
foreach ($pending in ($pendingPlans | Select-Object -First 15)) { Write-Host ('    {0,-32} {1,-36} {2}' -f $pending.SkuPartNumber, $pending.ServicePlanName, $pending.ProvisioningStatus) }
Write-Host ('  SKU/plan CSV                 : {0}' -f $skuPlansPath)
if ($includeUsers) {
    $distinctUsers = @($userRows | Select-Object -ExpandProperty UserPrincipalName -Unique).Count
    if ([string]::IsNullOrWhiteSpace($ServicePlanName)) { Write-Host ('  Licensed users / SKU rows    : {0} / {1}' -f $distinctUsers, $userRows.Count) }
    elseif ($ShowUsersWithoutPlan) { Write-Host ('  Users WITHOUT {0,-14} : {1} of {2} licensed' -f $ServicePlanName, $distinctUsers, $users.Count) -ForegroundColor Yellow }
    else { Write-Host ('  Users with {0,-17} : {1} of {2} licensed' -f $ServicePlanName, $distinctUsers, $users.Count) }
    $topDisabled = @($userRows | ForEach-Object { $_.DisabledPlans -split ';' } | Where-Object { -not [string]::IsNullOrEmpty($_) } | Group-Object | Sort-Object -Property Count -Descending)
    Write-Host '  Most commonly disabled plans :'
    foreach ($disabledGroup in ($topDisabled | Select-Object -First 10)) { Write-Host ('    {0,-36} {1,6}' -f $disabledGroup.Name, $disabledGroup.Count) }
    Write-Host ('  User CSV                     : {0}' -f $OutputPath)
}
if ($PassThru) { $skuPlanOutput; if ($includeUsers) { $userRows } }
#endregion Main
