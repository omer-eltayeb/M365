<#
.SYNOPSIS
    Assigns and removes Microsoft 365 licenses for one user or a CSV of users, with pre-flight checks and a results CSV.
.DESCRIPTION
    Resolves SKU part numbers (for example SPE_E3) or SKU ids against /subscribedSkus, reads each user from /users/{upn}
    and sends one POST /users/{id}/assignLicense per user with all additions, removals and disabled service plans.
    Before assigning it checks the usage location (set with -DefaultUsageLocation via PATCH when missing), that the SKU still
    has units left (enabled minus consumed, tracked during the run) and skips SKUs already assigned. One result row per user.
.PARAMETER InputCsv
    CSV with the columns UserPrincipalName, AddSku, RemoveSku, DisabledPlans (last three optional; semicolon-separated values).
.PARAMETER UserPrincipalName
    Single user to change instead of a CSV.
.PARAMETER AddSku
    SKU part numbers or SKU ids to assign to the single user.
.PARAMETER RemoveSku
    SKU part numbers or SKU ids to remove from the single user.
.PARAMETER DisabledPlans
    Service plan names (for example MCOSTANDARD, YAMMER_ENTERPRISE) to disable in every SKU that is being assigned.
.PARAMETER DefaultUsageLocation
    Two-letter ISO country code written to users without a usage location before a license is assigned.
.PARAMETER OutputPath
    Path of the results CSV. Defaults to .\Reports\M365LicenseChanges_<timestamp>.csv.
.EXAMPLE
    PS> .\Set-M365UserLicenses.ps1 -UserPrincipalName jdoe@contoso.com -AddSku SPE_E3 -DisabledPlans MCOSTANDARD,YAMMER_ENTERPRISE -WhatIf
    Shows the assignment that would be made (E3 with Skype for Business and Viva Engage disabled) without changing anything.
.EXAMPLE
    PS> .\Set-M365UserLicenses.ps1 -InputCsv .\licenses.csv -DefaultUsageLocation GB -Confirm:$false -Verbose
    Processes every CSV row, sets GB as usage location where missing and writes the results CSV without prompting per user.
.NOTES
    Author      : Omer Eltayeb
    Blog        : https://www.oeltayeb.com
    GitHub      : https://github.com/omer-eltayeb
    Version     : 1.0.0
    Created     : 2026-10-04
    Requires    : PowerShell 5.1 or 7.x, Microsoft.Graph.Authentication
    Permissions : User.ReadWrite.All, Organization.Read.All (delegated); License Administrator or User Administrator role.
    Category    : Licensing
    Changes     : Yes
    Notes       : A SKU the user already holds is skipped unless -DisabledPlans is given; Graph then treats the addLicenses entry as
                  an update and REPLACES that SKU's disabled plan set. Unknown plan names are ignored; group-inherited licenses cannot be removed here.
.LINK
    https://learn.microsoft.com/graph/api/user-assignlicense
#>
#Requires -Version 5.1
#Requires -Modules Microsoft.Graph.Authentication

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High', DefaultParameterSetName = 'Single')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Csv')]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$InputCsv,

    [Parameter(Mandatory = $true, ParameterSetName = 'Single')]
    [string]$UserPrincipalName,

    [Parameter(ParameterSetName = 'Single')]
    [string[]]$AddSku,

    [Parameter(ParameterSetName = 'Single')]
    [string[]]$RemoveSku,

    [Parameter(ParameterSetName = 'Single')]
    [string[]]$DisabledPlans,

    [Parameter()]
    [ValidatePattern('^[A-Za-z]{2}$')]
    [string]$DefaultUsageLocation,

    [Parameter()]
    [string]$OutputPath
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

function Split-Tokens {
    <# Splits a semicolon/comma separated CSV cell or a string array into trimmed, non-empty tokens. #>
    param([Parameter()][AllowNull()]$Value)
    return @((@($Value) -join ';') -split '[;,]' | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrEmpty($_) })
}
#endregion Helpers

#region Main
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $reportFolder = Join-Path -Path (Get-Location).Path -ChildPath 'Reports'
    $OutputPath = Join-Path -Path $reportFolder -ChildPath ('M365LicenseChanges_{0}.csv' -f (Get-Date -Format 'yyyyMMdd-HHmm'))
}
$outputFolder = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputFolder) -and -not (Test-Path -Path $outputFolder)) {
    New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
}
$workItems = @([PSCustomObject]@{ UserPrincipalName = $UserPrincipalName; AddSku = $AddSku; RemoveSku = $RemoveSku; DisabledPlans = $DisabledPlans })
if ($PSCmdlet.ParameterSetName -eq 'Csv') {
    $workItems = @(Import-Csv -Path $InputCsv | Where-Object { -not [string]::IsNullOrWhiteSpace($_.UserPrincipalName) })
    if ($workItems.Count -eq 0) { throw "No rows with a UserPrincipalName were found in $InputCsv." }
}
try { Connect-GraphIfNeeded -Scopes @('User.ReadWrite.All', 'Organization.Read.All') }
catch { throw "Failed to connect to Microsoft Graph: $($_.Exception.Message)" }
try { $skus = @(Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/subscribedSkus?$select=skuId,skuPartNumber,prepaidUnits,consumedUnits,servicePlans') }
catch { throw "Failed to read subscribed SKUs: $($_.Exception.Message)" }
# Hashtable keys are case-insensitive, so one table resolves part numbers and SKU ids; units are tracked locally so a bulk run cannot overshoot.
$skuByKey = @{}
$available = @{}
foreach ($sku in $skus) {
    $skuByKey[[string]$sku.skuPartNumber] = $sku
    $skuByKey[[string]$sku.skuId] = $sku
    $available[[string]$sku.skuId] = [int]$sku.prepaidUnits.enabled - [int]$sku.consumedUnits
}
$results = New-Object -TypeName System.Collections.Generic.List[object]
$counter = 0
foreach ($item in $workItems) {
    $counter++
    $upn = ([string]$item.UserPrincipalName).Trim()
    Write-Progress -Activity 'Processing license changes' -Status "$counter of $($workItems.Count): $upn" -PercentComplete ([int](($counter / $workItems.Count) * 100))
    $planNames = @(Split-Tokens -Value $item.DisabledPlans)
    $row = [PSCustomObject]@{ UserPrincipalName = $upn; SkusAdded = ''; SkusRemoved = ''; DisabledPlans = ($planNames -join ';'); UsageLocation = ''; Status = 'Skipped'; Error = '' }
    $results.Add($row)
    $userUri = 'https://graph.microsoft.com/v1.0/users/{0}?$select=id,usageLocation,assignedLicenses' -f [uri]::EscapeDataString($upn)
    try { $user = Invoke-MgGraphRequest -Method GET -Uri $userUri -OutputType PSObject }
    catch { $row.Status = 'Failed'; $row.Error = "User lookup failed: $($_.Exception.Message)"; Write-Warning "$upn - $($row.Error)"; continue }
    $row.UsageLocation = $user.usageLocation
    $assignedIds = @($user.assignedLicenses | ForEach-Object { [string]$_.skuId })
    $addLicenses = @(); $removeLicenses = @(); $problems = @()
    foreach ($token in @(Split-Tokens -Value $item.AddSku)) {
        $sku = $skuByKey[$token]
        if ($null -eq $sku) { $problems += "Unknown SKU '$token'"; continue }
        $alreadyAssigned = $assignedIds -contains [string]$sku.skuId
        if ($alreadyAssigned -and $planNames.Count -eq 0) { Write-Verbose "$upn already has $($sku.skuPartNumber)."; continue }
        if (-not $alreadyAssigned -and $available[[string]$sku.skuId] -le 0) { $problems += "License not available ($($sku.skuPartNumber) has 0 units left)"; continue }
        $disabledIds = @($sku.servicePlans | Where-Object { $planNames -contains $_.servicePlanName } | ForEach-Object { [string]$_.servicePlanId })
        $addLicenses += @{ skuId = [string]$sku.skuId; disabledPlans = $disabledIds }
    }
    foreach ($token in @(Split-Tokens -Value $item.RemoveSku)) {
        $sku = $skuByKey[$token]
        if ($null -eq $sku) { $problems += "Unknown SKU '$token'"; continue }
        if ($assignedIds -contains [string]$sku.skuId) { $removeLicenses += [string]$sku.skuId } else { Write-Verbose "$upn does not have $($sku.skuPartNumber)." }
    }
    if ($addLicenses.Count -gt 0 -and [string]::IsNullOrWhiteSpace($user.usageLocation)) {
        if ([string]::IsNullOrWhiteSpace($DefaultUsageLocation)) { $problems += 'No usage location set (use -DefaultUsageLocation)'; $addLicenses = @() }
        elseif ($PSCmdlet.ShouldProcess($upn, "Set usage location to $($DefaultUsageLocation.ToUpper())")) {
            try {
                $patchBody = @{ usageLocation = $DefaultUsageLocation.ToUpper() } | ConvertTo-Json
                Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/users/$($user.id)" -Body $patchBody -ContentType 'application/json' | Out-Null
                $row.UsageLocation = $DefaultUsageLocation.ToUpper()
            }
            catch { $problems += "Usage location update failed: $($_.Exception.Message)"; $addLicenses = @() }
        }
    }
    $row.Error = ($problems -join '; ')
    if ($addLicenses.Count -eq 0 -and $removeLicenses.Count -eq 0) {
        if ($problems.Count -gt 0) { $row.Status = 'Failed'; Write-Warning "$upn - $($row.Error)" } else { $row.Status = 'NoChange' }
        continue
    }
    $row.SkusAdded = (@($addLicenses | ForEach-Object { $skuByKey[$_.skuId].skuPartNumber }) -join ';')
    $row.SkusRemoved = (@($removeLicenses | ForEach-Object { $skuByKey[$_].skuPartNumber }) -join ';')
    if (-not $PSCmdlet.ShouldProcess($upn, "Assign [$($row.SkusAdded)] / remove [$($row.SkusRemoved)]")) { continue }
    try {
        $body = @{ addLicenses = @($addLicenses); removeLicenses = @($removeLicenses) } | ConvertTo-Json -Depth 5
        Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/users/$($user.id)/assignLicense" -Body $body -ContentType 'application/json' | Out-Null
        foreach ($license in $addLicenses) { if ($assignedIds -notcontains $license.skuId) { $available[$license.skuId]-- } }
        foreach ($removedId in $removeLicenses) { $available[$removedId]++ }
        $row.Status = 'Success'
    }
    catch { $row.Status = 'Failed'; $row.Error = (@($problems + "assignLicense failed: $($_.Exception.Message)") -join '; '); Write-Warning "$upn - $($_.Exception.Message)" }
    Start-Sleep -Milliseconds 200
}
Write-Progress -Activity 'Processing license changes' -Completed
$results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Write-Host ('License change summary ({0} users)' -f $results.Count) -ForegroundColor Cyan
foreach ($statusGroup in ($results | Group-Object -Property Status | Sort-Object -Property Name)) { Write-Host ('  {0,-16}: {1}' -f $statusGroup.Name, $statusGroup.Count) }
Write-Host ('  Results CSV     : {0}' -f $OutputPath)
#endregion Main
